//! Circuit Breaker + Upstream Health Checks.
//!
//! Per-upstream circuit breaker with three states:
//! - Closed: normal operation, requests flow through
//! - Open: upstream considered down, requests fail fast with 503
//! - HalfOpen: allow a single probe request to test recovery
//!
//! Includes periodic health checking of upstream services.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use tracing::{info, warn};

/// Circuit breaker state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitState {
    /// Normal operation — requests pass through.
    Closed,
    /// Upstream is considered down — fail fast.
    Open,
    /// Testing recovery — allow one probe request.
    HalfOpen,
}

impl std::fmt::Display for CircuitState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Closed => write!(f, "closed"),
            Self::Open => write!(f, "open"),
            Self::HalfOpen => write!(f, "half-open"),
        }
    }
}

/// Configuration for a circuit breaker.
#[derive(Debug, Clone)]
pub struct CircuitBreakerConfig {
    /// Number of consecutive failures to trip the circuit.
    pub failure_threshold: u32,
    /// How long to wait in Open state before trying HalfOpen.
    pub recovery_timeout: Duration,
    /// Health check interval.
    pub health_check_interval: Duration,
    /// Health check path on the upstream.
    pub health_check_path: String,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 5,
            recovery_timeout: Duration::from_secs(30),
            health_check_interval: Duration::from_secs(10),
            health_check_path: "/health".to_string(),
        }
    }
}

/// Per-upstream circuit breaker state.
#[derive(Debug)]
struct UpstreamCircuit {
    state: CircuitState,
    consecutive_failures: u32,
    last_failure_time: Option<Instant>,
    last_success_time: Option<Instant>,
    last_health_check: Option<Instant>,
    total_requests: u64,
    total_failures: u64,
    total_circuit_opens: u64,
    config: CircuitBreakerConfig,
    healthy: bool,
}

impl UpstreamCircuit {
    fn new(config: CircuitBreakerConfig) -> Self {
        Self {
            state: CircuitState::Closed,
            consecutive_failures: 0,
            last_failure_time: None,
            last_success_time: None,
            last_health_check: None,
            total_requests: 0,
            total_failures: 0,
            total_circuit_opens: 0,
            config,
            healthy: true,
        }
    }
}

/// Manages circuit breakers for all upstream services.
#[derive(Clone)]
pub struct CircuitBreakerManager {
    circuits: Arc<RwLock<HashMap<String, UpstreamCircuit>>>,
    default_config: CircuitBreakerConfig,
}

impl CircuitBreakerManager {
    pub fn new(default_config: CircuitBreakerConfig) -> Self {
        Self {
            circuits: Arc::new(RwLock::new(HashMap::new())),
            default_config,
        }
    }

    /// Register an upstream with optional custom config.
    pub fn register_upstream(&self, upstream: &str, config: Option<CircuitBreakerConfig>) {
        let mut circuits = self.circuits.write().unwrap();
        if !circuits.contains_key(upstream) {
            let cfg = config.unwrap_or_else(|| self.default_config.clone());
            info!(upstream = %upstream, threshold = cfg.failure_threshold, "Circuit breaker registered");
            circuits.insert(upstream.to_string(), UpstreamCircuit::new(cfg));
        }
    }

    /// Check if a request to this upstream should be allowed.
    /// Returns Ok(()) if allowed, Err(CircuitState::Open) if blocked.
    pub fn check_request(&self, upstream: &str) -> Result<(), CircuitState> {
        let mut circuits = self.circuits.write().unwrap();
        let circuit = circuits
            .entry(upstream.to_string())
            .or_insert_with(|| UpstreamCircuit::new(self.default_config.clone()));

        circuit.total_requests += 1;

        match circuit.state {
            CircuitState::Closed => Ok(()),
            CircuitState::Open => {
                // Check if recovery timeout has elapsed
                if let Some(last_fail) = circuit.last_failure_time {
                    if last_fail.elapsed() >= circuit.config.recovery_timeout {
                        circuit.state = CircuitState::HalfOpen;
                        info!(upstream = %upstream, "Circuit breaker → half-open (recovery timeout elapsed)");
                        return Ok(());
                    }
                }
                Err(CircuitState::Open)
            }
            CircuitState::HalfOpen => {
                // Allow one probe request
                Ok(())
            }
        }
    }

    /// Record a successful response from an upstream.
    pub fn record_success(&self, upstream: &str) {
        let mut circuits = self.circuits.write().unwrap();
        if let Some(circuit) = circuits.get_mut(upstream) {
            let was_half_open = circuit.state == CircuitState::HalfOpen;
            circuit.consecutive_failures = 0;
            circuit.last_success_time = Some(Instant::now());
            circuit.state = CircuitState::Closed;
            circuit.healthy = true;

            if was_half_open {
                info!(upstream = %upstream, "Circuit breaker → closed (probe succeeded)");
            }
        }
    }

    /// Record a failure from an upstream.
    pub fn record_failure(&self, upstream: &str) {
        let mut circuits = self.circuits.write().unwrap();
        let circuit = circuits
            .entry(upstream.to_string())
            .or_insert_with(|| UpstreamCircuit::new(self.default_config.clone()));

        circuit.consecutive_failures += 1;
        circuit.total_failures += 1;
        circuit.last_failure_time = Some(Instant::now());

        match circuit.state {
            CircuitState::HalfOpen => {
                // Probe failed — back to Open
                circuit.state = CircuitState::Open;
                circuit.total_circuit_opens += 1;
                warn!(upstream = %upstream, "Circuit breaker → open (probe failed)");
            }
            CircuitState::Closed => {
                if circuit.consecutive_failures >= circuit.config.failure_threshold {
                    circuit.state = CircuitState::Open;
                    circuit.total_circuit_opens += 1;
                    circuit.healthy = false;
                    warn!(
                        upstream = %upstream,
                        failures = circuit.consecutive_failures,
                        threshold = circuit.config.failure_threshold,
                        "Circuit breaker → open (failure threshold reached)"
                    );
                }
            }
            CircuitState::Open => {
                // Already open
            }
        }
    }

    /// Update health check result for an upstream.
    pub fn update_health(&self, upstream: &str, healthy: bool) {
        let mut circuits = self.circuits.write().unwrap();
        if let Some(circuit) = circuits.get_mut(upstream) {
            circuit.last_health_check = Some(Instant::now());
            circuit.healthy = healthy;

            if healthy && circuit.state == CircuitState::Open {
                circuit.state = CircuitState::HalfOpen;
                info!(upstream = %upstream, "Health check passed → half-open");
            } else if !healthy && circuit.state == CircuitState::Closed {
                circuit.consecutive_failures += 1;
                if circuit.consecutive_failures >= circuit.config.failure_threshold {
                    circuit.state = CircuitState::Open;
                    circuit.total_circuit_opens += 1;
                    warn!(upstream = %upstream, "Health check failed → open");
                }
            }
        }
    }

    /// Get the current state of all circuit breakers.
    pub fn get_status(&self) -> HashMap<String, CircuitBreakerStatus> {
        let circuits = self.circuits.read().unwrap();
        circuits
            .iter()
            .map(|(upstream, circuit)| {
                (
                    upstream.clone(),
                    CircuitBreakerStatus {
                        state: circuit.state,
                        consecutive_failures: circuit.consecutive_failures,
                        total_requests: circuit.total_requests,
                        total_failures: circuit.total_failures,
                        total_circuit_opens: circuit.total_circuit_opens,
                        healthy: circuit.healthy,
                    },
                )
            })
            .collect()
    }

    /// Get the state for a specific upstream.
    pub fn get_upstream_state(&self, upstream: &str) -> Option<CircuitState> {
        self.circuits
            .read()
            .unwrap()
            .get(upstream)
            .map(|c| c.state)
    }

    /// Check if an upstream needs a health check.
    pub fn needs_health_check(&self, upstream: &str) -> bool {
        let circuits = self.circuits.read().unwrap();
        if let Some(circuit) = circuits.get(upstream) {
            match circuit.last_health_check {
                Some(last) => last.elapsed() >= circuit.config.health_check_interval,
                None => true,
            }
        } else {
            false
        }
    }

    /// Get all registered upstream URLs that need health checks.
    pub fn upstreams_needing_health_check(&self) -> Vec<(String, String)> {
        let circuits = self.circuits.read().unwrap();
        circuits
            .iter()
            .filter(|(_, c)| {
                c.last_health_check
                    .map(|t| t.elapsed() >= c.config.health_check_interval)
                    .unwrap_or(true)
            })
            .map(|(u, c)| (u.clone(), c.config.health_check_path.clone()))
            .collect()
    }
}

/// Public status info for a circuit breaker.
#[derive(Debug, Clone)]
pub struct CircuitBreakerStatus {
    pub state: CircuitState,
    pub consecutive_failures: u32,
    pub total_requests: u64,
    pub total_failures: u64,
    pub total_circuit_opens: u64,
    pub healthy: bool,
}

/// Run periodic health checks against upstreams.
/// This should be spawned as a background task.
pub async fn run_health_checks(
    cb_manager: CircuitBreakerManager,
    interval: Duration,
) {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new());

    loop {
        tokio::time::sleep(interval).await;

        let targets = cb_manager.upstreams_needing_health_check();
        for (upstream, health_path) in targets {
            let url = format!("{upstream}{health_path}");
            let healthy = match client.get(&url).send().await {
                Ok(resp) => resp.status().is_success(),
                Err(_) => false,
            };
            cb_manager.update_health(&upstream, healthy);
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_config(threshold: u32, recovery_secs: u64) -> CircuitBreakerConfig {
        CircuitBreakerConfig {
            failure_threshold: threshold,
            recovery_timeout: Duration::from_secs(recovery_secs),
            health_check_interval: Duration::from_secs(10),
            health_check_path: "/health".to_string(),
        }
    }

    #[test]
    fn test_initial_state_closed() {
        let mgr = CircuitBreakerManager::new(make_config(3, 30));
        mgr.register_upstream("http://upstream:9001", None);
        assert_eq!(
            mgr.get_upstream_state("http://upstream:9001"),
            Some(CircuitState::Closed)
        );
    }

    #[test]
    fn test_circuit_opens_on_threshold() {
        let mgr = CircuitBreakerManager::new(make_config(3, 30));
        let upstream = "http://upstream:9001";
        mgr.register_upstream(upstream, None);

        // 2 failures: still closed
        mgr.record_failure(upstream);
        mgr.record_failure(upstream);
        assert_eq!(mgr.get_upstream_state(upstream), Some(CircuitState::Closed));

        // 3rd failure: opens
        mgr.record_failure(upstream);
        assert_eq!(mgr.get_upstream_state(upstream), Some(CircuitState::Open));
    }

    #[test]
    fn test_open_circuit_blocks_requests() {
        let mgr = CircuitBreakerManager::new(make_config(2, 300));
        let upstream = "http://upstream:9001";
        mgr.register_upstream(upstream, None);

        mgr.record_failure(upstream);
        mgr.record_failure(upstream);

        let result = mgr.check_request(upstream);
        assert_eq!(result, Err(CircuitState::Open));
    }

    #[test]
    fn test_success_resets_failure_count() {
        let mgr = CircuitBreakerManager::new(make_config(3, 30));
        let upstream = "http://upstream:9001";
        mgr.register_upstream(upstream, None);

        mgr.record_failure(upstream);
        mgr.record_failure(upstream);
        mgr.record_success(upstream);

        // Should be back to closed with 0 failures
        assert_eq!(mgr.get_upstream_state(upstream), Some(CircuitState::Closed));

        // Need 3 more failures to open again
        mgr.record_failure(upstream);
        mgr.record_failure(upstream);
        assert_eq!(mgr.get_upstream_state(upstream), Some(CircuitState::Closed));
    }

    #[test]
    fn test_half_open_on_recovery_timeout() {
        let mgr = CircuitBreakerManager::new(make_config(2, 0)); // 0 second recovery
        let upstream = "http://upstream:9001";
        mgr.register_upstream(upstream, None);

        mgr.record_failure(upstream);
        mgr.record_failure(upstream);
        assert_eq!(mgr.get_upstream_state(upstream), Some(CircuitState::Open));

        // With 0s recovery, check_request should transition to half-open
        std::thread::sleep(Duration::from_millis(10));
        let result = mgr.check_request(upstream);
        assert!(result.is_ok());
        assert_eq!(
            mgr.get_upstream_state(upstream),
            Some(CircuitState::HalfOpen)
        );
    }

    #[test]
    fn test_half_open_success_closes() {
        let mgr = CircuitBreakerManager::new(make_config(2, 0));
        let upstream = "http://upstream:9001";
        mgr.register_upstream(upstream, None);

        mgr.record_failure(upstream);
        mgr.record_failure(upstream);
        std::thread::sleep(Duration::from_millis(10));
        mgr.check_request(upstream).ok();

        mgr.record_success(upstream);
        assert_eq!(mgr.get_upstream_state(upstream), Some(CircuitState::Closed));
    }

    #[test]
    fn test_half_open_failure_reopens() {
        let mgr = CircuitBreakerManager::new(make_config(2, 0));
        let upstream = "http://upstream:9001";
        mgr.register_upstream(upstream, None);

        mgr.record_failure(upstream);
        mgr.record_failure(upstream);
        std::thread::sleep(Duration::from_millis(10));
        mgr.check_request(upstream).ok();

        mgr.record_failure(upstream);
        assert_eq!(mgr.get_upstream_state(upstream), Some(CircuitState::Open));
    }

    #[test]
    fn test_get_status() {
        let mgr = CircuitBreakerManager::new(make_config(3, 30));
        mgr.register_upstream("http://a:9001", None);
        mgr.register_upstream("http://b:9002", None);
        mgr.record_failure("http://a:9001");
        mgr.check_request("http://a:9001").ok();
        mgr.check_request("http://b:9002").ok();

        let status = mgr.get_status();
        assert_eq!(status.len(), 2);
        let a = &status["http://a:9001"];
        assert_eq!(a.consecutive_failures, 1);
        assert_eq!(a.total_requests, 1);
    }

    #[test]
    fn test_health_check_opens_circuit() {
        let mgr = CircuitBreakerManager::new(make_config(2, 30));
        let upstream = "http://upstream:9001";
        mgr.register_upstream(upstream, None);

        mgr.update_health(upstream, false);
        mgr.update_health(upstream, false);
        assert_eq!(mgr.get_upstream_state(upstream), Some(CircuitState::Open));
    }

    #[test]
    fn test_health_check_recovery() {
        let mgr = CircuitBreakerManager::new(make_config(2, 30));
        let upstream = "http://upstream:9001";
        mgr.register_upstream(upstream, None);

        mgr.record_failure(upstream);
        mgr.record_failure(upstream);
        assert_eq!(mgr.get_upstream_state(upstream), Some(CircuitState::Open));

        // Health check success should transition to half-open
        mgr.update_health(upstream, true);
        assert_eq!(
            mgr.get_upstream_state(upstream),
            Some(CircuitState::HalfOpen)
        );
    }

    #[test]
    fn test_auto_register_on_check() {
        let mgr = CircuitBreakerManager::new(make_config(3, 30));
        // Not explicitly registered
        let result = mgr.check_request("http://new:9001");
        assert!(result.is_ok());
        assert_eq!(
            mgr.get_upstream_state("http://new:9001"),
            Some(CircuitState::Closed)
        );
    }
}