//! Token-bucket rate limiter.
//!
//! Provides per-route and per-IP rate limiting using a sliding-window
//! token bucket implementation backed by DashMap.

use dashmap::DashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::warn;

/// Per-key rate limit state.
#[derive(Debug, Clone)]
struct Bucket {
    tokens: f64,
    last_refill: Instant,
    capacity: f64,
    refill_rate: f64, // tokens per second
}

impl Bucket {
    fn new(capacity: u32, window_seconds: u64) -> Self {
        let cap = capacity as f64;
        Self {
            tokens: cap,
            last_refill: Instant::now(),
            capacity: cap,
            refill_rate: cap / window_seconds as f64,
        }
    }

    /// Try to consume one token. Returns true if allowed.
    fn try_consume(&mut self) -> bool {
        self.refill();
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.refill_rate).min(self.capacity);
        self.last_refill = now;
    }

    /// Estimated seconds until a token is available.
    fn retry_after(&self) -> f64 {
        if self.tokens >= 1.0 {
            return 0.0;
        }
        (1.0 - self.tokens) / self.refill_rate
    }
}

/// Composite key for rate limiting: route_id + client_ip.
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct RateLimitKey {
    pub route_id: String,
    pub client_ip: String,
}

/// Rate limiter managing per-key buckets.
#[derive(Clone)]
pub struct RateLimiter {
    buckets: Arc<DashMap<RateLimitKey, Bucket>>,
    default_capacity: u32,
    default_window: u64,
}

/// Result of a rate limit check.
#[derive(Debug, Clone)]
pub enum RateLimitResult {
    Allowed,
    Limited { retry_after_secs: f64 },
}

impl RateLimiter {
    pub fn new(default_capacity: u32, default_window_seconds: u64) -> Self {
        Self {
            buckets: Arc::new(DashMap::new()),
            default_capacity,
            default_window: default_window_seconds,
        }
    }

    /// Check if a request is allowed under rate limits.
    /// `route_limit` overrides the default if provided.
    pub fn check(
        &self,
        key: &RateLimitKey,
        route_limit: Option<(u32, u64)>,
    ) -> RateLimitResult {
        let (capacity, window) = route_limit.unwrap_or((self.default_capacity, self.default_window));

        let mut entry = self.buckets
            .entry(key.clone())
            .or_insert_with(|| Bucket::new(capacity, window));

        if entry.try_consume() {
            RateLimitResult::Allowed
        } else {
            let retry = entry.retry_after();
            warn!(
                route = %key.route_id,
                client = %key.client_ip,
                retry_after = retry,
                "Rate limit exceeded"
            );
            RateLimitResult::Limited { retry_after_secs: retry }
        }
    }

    /// Evict stale entries older than the given duration.
    pub fn cleanup(&self, max_age: Duration) {
        let now = Instant::now();
        self.buckets.retain(|_, bucket| {
            now.duration_since(bucket.last_refill) < max_age
        });
    }

    /// Number of tracked keys.
    pub fn key_count(&self) -> usize {
        self.buckets.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_key(route: &str, ip: &str) -> RateLimitKey {
        RateLimitKey {
            route_id: route.to_string(),
            client_ip: ip.to_string(),
        }
    }

    #[test]
    fn test_allows_within_limit() {
        let rl = RateLimiter::new(5, 60);
        let key = make_key("r1", "1.2.3.4");
        for _ in 0..5 {
            assert!(matches!(rl.check(&key, None), RateLimitResult::Allowed));
        }
    }

    #[test]
    fn test_blocks_over_limit() {
        let rl = RateLimiter::new(3, 60);
        let key = make_key("r1", "1.2.3.4");
        for _ in 0..3 {
            assert!(matches!(rl.check(&key, None), RateLimitResult::Allowed));
        }
        assert!(matches!(rl.check(&key, None), RateLimitResult::Limited { .. }));
    }

    #[test]
    fn test_different_keys_independent() {
        let rl = RateLimiter::new(2, 60);
        let key1 = make_key("r1", "1.1.1.1");
        let key2 = make_key("r1", "2.2.2.2");
        assert!(matches!(rl.check(&key1, None), RateLimitResult::Allowed));
        assert!(matches!(rl.check(&key1, None), RateLimitResult::Allowed));
        assert!(matches!(rl.check(&key1, None), RateLimitResult::Limited { .. }));
        // key2 should still be allowed
        assert!(matches!(rl.check(&key2, None), RateLimitResult::Allowed));
    }

    #[test]
    fn test_route_override() {
        let rl = RateLimiter::new(100, 60);
        let key = make_key("r1", "1.1.1.1");
        // Override with a limit of 1
        assert!(matches!(rl.check(&key, Some((1, 60))), RateLimitResult::Allowed));
        assert!(matches!(rl.check(&key, Some((1, 60))), RateLimitResult::Limited { .. }));
    }

    #[test]
    fn test_refill_over_time() {
        let rl = RateLimiter::new(1, 1); // 1 req/sec
        let key = make_key("r1", "1.1.1.1");
        assert!(matches!(rl.check(&key, None), RateLimitResult::Allowed));
        assert!(matches!(rl.check(&key, None), RateLimitResult::Limited { .. }));
        // Wait a bit for refill
        std::thread::sleep(std::time::Duration::from_millis(1100));
        assert!(matches!(rl.check(&key, None), RateLimitResult::Allowed));
    }

    #[test]
    fn test_cleanup() {
        let rl = RateLimiter::new(10, 60);
        let key = make_key("r1", "1.1.1.1");
        rl.check(&key, None);
        assert_eq!(rl.key_count(), 1);
        // Cleanup with zero max_age removes everything
        rl.cleanup(Duration::from_secs(0));
        assert_eq!(rl.key_count(), 0);
    }

    #[test]
    fn test_retry_after_value() {
        let rl = RateLimiter::new(1, 60);
        let key = make_key("r1", "1.1.1.1");
        rl.check(&key, None); // consume the one token
        if let RateLimitResult::Limited { retry_after_secs } = rl.check(&key, None) {
            assert!(retry_after_secs > 0.0);
            assert!(retry_after_secs <= 60.0);
        } else {
            panic!("Expected Limited");
        }
    }
}
