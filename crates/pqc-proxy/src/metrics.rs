//! Prometheus-compatible metrics for the gateway.
//!
//! Tracks request counts, latencies, circuit breaker states,
//! rate limit rejections, and upstream health.

use dashmap::DashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

/// Central metrics registry.
#[derive(Clone)]
pub struct GatewayMetrics {
    inner: Arc<MetricsInner>,
}

struct MetricsInner {
    /// Total requests by route + method + status.
    request_counters: DashMap<RequestKey, AtomicU64>,
    /// Total upstream failures.
    upstream_failures: AtomicU64,
    /// Total rate limit rejections.
    rate_limit_rejections: AtomicU64,
    /// Total circuit breaker rejections.
    circuit_breaker_rejections: AtomicU64,
    /// Total auth failures.
    auth_failures: AtomicU64,
    /// Total requests proxied.
    total_requests: AtomicU64,
    /// Active connections gauge.
    active_connections: AtomicU64,
    /// Histogram buckets for request duration (milliseconds).
    duration_buckets: DashMap<String, Vec<u64>>,
    /// Readiness state.
    ready: std::sync::atomic::AtomicBool,
}

#[derive(Debug, Clone, Hash, Eq, PartialEq)]
struct RequestKey {
    route_id: String,
    method: String,
    status: u16,
}

impl GatewayMetrics {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(MetricsInner {
                request_counters: DashMap::new(),
                upstream_failures: AtomicU64::new(0),
                rate_limit_rejections: AtomicU64::new(0),
                circuit_breaker_rejections: AtomicU64::new(0),
                auth_failures: AtomicU64::new(0),
                total_requests: AtomicU64::new(0),
                active_connections: AtomicU64::new(0),
                duration_buckets: DashMap::new(),
                ready: std::sync::atomic::AtomicBool::new(true),
            }),
        }
    }

    pub fn record_request(&self, route_id: &str, method: &str, status: u16, duration_ms: u64) {
        self.inner.total_requests.fetch_add(1, Ordering::Relaxed);

        let key = RequestKey {
            route_id: route_id.to_string(),
            method: method.to_string(),
            status,
        };
        self.inner.request_counters
            .entry(key)
            .or_insert_with(|| AtomicU64::new(0))
            .fetch_add(1, Ordering::Relaxed);

        self.inner.duration_buckets
            .entry(route_id.to_string())
            .or_insert_with(Vec::new)
            .push(duration_ms);
    }

    pub fn record_upstream_failure(&self) {
        self.inner.upstream_failures.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_rate_limit_rejection(&self) {
        self.inner.rate_limit_rejections.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_circuit_breaker_rejection(&self) {
        self.inner.circuit_breaker_rejections.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_auth_failure(&self) {
        self.inner.auth_failures.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_active_connections(&self) {
        self.inner.active_connections.fetch_add(1, Ordering::Relaxed);
    }

    pub fn dec_active_connections(&self) {
        self.inner.active_connections.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn set_ready(&self, ready: bool) {
        self.inner.ready.store(ready, Ordering::Relaxed);
    }

    pub fn is_ready(&self) -> bool {
        self.inner.ready.load(Ordering::Relaxed)
    }

    pub fn total_requests(&self) -> u64 {
        self.inner.total_requests.load(Ordering::Relaxed)
    }

    /// Render Prometheus text exposition format.
    pub fn render_prometheus(&self) -> String {
        let mut out = String::new();

        // Total requests
        out.push_str("# HELP gateway_requests_total Total requests proxied.\n");
        out.push_str("# TYPE gateway_requests_total counter\n");
        for entry in self.inner.request_counters.iter() {
            let k = entry.key();
            let v = entry.value().load(Ordering::Relaxed);
            out.push_str(&format!(
                "gateway_requests_total{{route=\"{}\",method=\"{}\",status=\"{}\"}} {}\n",
                k.route_id, k.method, k.status, v
            ));
        }

        out.push_str("# HELP gateway_upstream_failures_total Total upstream failures.\n");
        out.push_str("# TYPE gateway_upstream_failures_total counter\n");
        out.push_str(&format!(
            "gateway_upstream_failures_total {}\n",
            self.inner.upstream_failures.load(Ordering::Relaxed)
        ));

        out.push_str("# HELP gateway_rate_limit_rejections_total Total rate limit rejections.\n");
        out.push_str("# TYPE gateway_rate_limit_rejections_total counter\n");
        out.push_str(&format!(
            "gateway_rate_limit_rejections_total {}\n",
            self.inner.rate_limit_rejections.load(Ordering::Relaxed)
        ));

        out.push_str("# HELP gateway_circuit_breaker_rejections_total Total circuit breaker rejections.\n");
        out.push_str("# TYPE gateway_circuit_breaker_rejections_total counter\n");
        out.push_str(&format!(
            "gateway_circuit_breaker_rejections_total {}\n",
            self.inner.circuit_breaker_rejections.load(Ordering::Relaxed)
        ));

        out.push_str("# HELP gateway_auth_failures_total Total authentication failures.\n");
        out.push_str("# TYPE gateway_auth_failures_total counter\n");
        out.push_str(&format!(
            "gateway_auth_failures_total {}\n",
            self.inner.auth_failures.load(Ordering::Relaxed)
        ));

        out.push_str("# HELP gateway_active_connections Current active connections.\n");
        out.push_str("# TYPE gateway_active_connections gauge\n");
        out.push_str(&format!(
            "gateway_active_connections {}\n",
            self.inner.active_connections.load(Ordering::Relaxed)
        ));

        out
    }

    /// Return a JSON summary suitable for admin endpoints.
    pub fn to_json(&self) -> serde_json::Value {
        let mut route_stats = serde_json::Map::new();
        for entry in self.inner.request_counters.iter() {
            let k = entry.key();
            let v = entry.value().load(Ordering::Relaxed);
            let key = format!("{}.{}.{}", k.route_id, k.method, k.status);
            route_stats.insert(key, serde_json::json!(v));
        }

        serde_json::json!({
            "total_requests": self.inner.total_requests.load(Ordering::Relaxed),
            "upstream_failures": self.inner.upstream_failures.load(Ordering::Relaxed),
            "rate_limit_rejections": self.inner.rate_limit_rejections.load(Ordering::Relaxed),
            "circuit_breaker_rejections": self.inner.circuit_breaker_rejections.load(Ordering::Relaxed),
            "auth_failures": self.inner.auth_failures.load(Ordering::Relaxed),
            "active_connections": self.inner.active_connections.load(Ordering::Relaxed),
            "ready": self.inner.ready.load(Ordering::Relaxed),
            "routes": route_stats,
        })
    }
}

impl Default for GatewayMetrics {
    fn default() -> Self {
        Self::new()
    }
}

/// Simple request duration tracker.
pub struct RequestTimer {
    start: Instant,
}

impl RequestTimer {
    pub fn start() -> Self {
        Self { start: Instant::now() }
    }

    pub fn elapsed_ms(&self) -> u64 {
        self.start.elapsed().as_millis() as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_new() {
        let m = GatewayMetrics::new();
        assert_eq!(m.total_requests(), 0);
        assert!(m.is_ready());
    }

    #[test]
    fn test_record_request() {
        let m = GatewayMetrics::new();
        m.record_request("r1", "GET", 200, 42);
        m.record_request("r1", "GET", 200, 50);
        m.record_request("r1", "POST", 201, 100);
        assert_eq!(m.total_requests(), 3);
    }

    #[test]
    fn test_prometheus_output() {
        let m = GatewayMetrics::new();
        m.record_request("r1", "GET", 200, 10);
        m.record_upstream_failure();
        m.record_rate_limit_rejection();
        m.record_circuit_breaker_rejection();
        m.record_auth_failure();

        let output = m.render_prometheus();
        assert!(output.contains("gateway_requests_total"));
        assert!(output.contains("gateway_upstream_failures_total 1"));
        assert!(output.contains("gateway_rate_limit_rejections_total 1"));
        assert!(output.contains("gateway_circuit_breaker_rejections_total 1"));
        assert!(output.contains("gateway_auth_failures_total 1"));
    }

    #[test]
    fn test_active_connections() {
        let m = GatewayMetrics::new();
        m.inc_active_connections();
        m.inc_active_connections();
        let json = m.to_json();
        assert_eq!(json["active_connections"], 2);
        m.dec_active_connections();
        let json = m.to_json();
        assert_eq!(json["active_connections"], 1);
    }

    #[test]
    fn test_readiness() {
        let m = GatewayMetrics::new();
        assert!(m.is_ready());
        m.set_ready(false);
        assert!(!m.is_ready());
        m.set_ready(true);
        assert!(m.is_ready());
    }

    #[test]
    fn test_json_output() {
        let m = GatewayMetrics::new();
        m.record_request("route-a", "GET", 200, 5);
        let json = m.to_json();
        assert_eq!(json["total_requests"], 1);
        assert!(json["ready"].as_bool().unwrap());
    }

    #[test]
    fn test_request_timer() {
        let timer = RequestTimer::start();
        std::thread::sleep(std::time::Duration::from_millis(10));
        assert!(timer.elapsed_ms() >= 10);
    }
}
