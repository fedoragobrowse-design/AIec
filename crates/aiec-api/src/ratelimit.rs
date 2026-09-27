//! Per-tenant and per-client rate limiting for the public API.
//!
//! One tenant must not be able to exhaust the API for everyone, so every
//! request to the protected surface is admitted against a token bucket keyed by
//! the authenticated tenant when there is one and by client address otherwise.
//! The limiter is deliberately in-process and dependency-free: a public alpha
//! runs a small number of API processes, and the durable quota system already
//! governs aggregate resource admission. Bounded state avoids an unbounded map
//! being grown by client-supplied addresses.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::Instant;

/// A single rate-limit rule: sustained rate with a burst ceiling.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct RateLimit {
    /// Sustained requests allowed per second.
    pub per_second: f64,
    /// Maximum requests allowed in a burst.
    pub burst: u32,
}

impl RateLimit {
    /// Builds a limit, treating non-positive rates as "deny everything" and
    /// clamping a burst below one request up to one.
    pub const fn new(per_second: f64, burst: u32) -> Self {
        let burst = if burst == 0 { 1 } else { burst };
        Self { per_second, burst }
    }

    fn refill_per_second(&self) -> f64 {
        if self.per_second.is_finite() && self.per_second > 0.0 {
            self.per_second
        } else {
            0.0
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct Bucket {
    tokens: f64,
    last_seen: Instant,
}

/// Bounded key -> bucket map implementing a token bucket per key.
#[derive(Debug)]
pub struct RateLimiter {
    limit: RateLimit,
    buckets: Mutex<HashMap<String, Bucket>>,
    capacity: usize,
}

impl RateLimiter {
    pub fn new(limit: RateLimit) -> Self {
        Self {
            limit,
            buckets: Mutex::new(HashMap::new()),
            // Bounded so client-supplied addresses cannot grow the map without
            // limit; oldest-style eviction is unnecessary at this scale.
            capacity: 50_000,
        }
    }

    /// Outcome of a single admission decision.
    pub fn check(&self, key: &str) -> Decision {
        self.check_at(key, Instant::now())
    }

    fn check_at(&self, key: &str, now: Instant) -> Decision {
        let refill = self.limit.refill_per_second();
        let burst = f64::from(self.limit.burst);
        if refill <= 0.0 {
            // A zero rate denies rather than silently allowing everything.
            return Decision::denied(0, 1);
        }
        let mut buckets = match self.buckets.lock() {
            Ok(guard) => guard,
            // A poisoned lock must not become an outage that admits everything.
            Err(poisoned) => poisoned.into_inner(),
        };
        if buckets.len() >= self.capacity && !buckets.contains_key(key) {
            buckets.clear();
        }
        let bucket = buckets.entry(key.to_string()).or_insert(Bucket {
            tokens: burst,
            last_seen: now,
        });
        let elapsed = now
            .saturating_duration_since(bucket.last_seen)
            .as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * refill).min(burst);
        bucket.last_seen = now;
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            Decision::allowed(self.retry_after(bucket, refill))
        } else {
            Decision::denied(self.retry_after(bucket, refill), 0)
        }
    }

    fn retry_after(&self, bucket: &Bucket, refill: f64) -> u64 {
        if refill <= 0.0 || bucket.tokens >= 1.0 {
            return 0;
        }
        let missing = 1.0 - bucket.tokens;
        // Round up so a client never retries before the bucket can admit it.
        (missing / refill).ceil().max(1.0) as u64
    }
}

/// Whether a request may proceed, and for how long it should back off.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Decision {
    pub allowed: bool,
    pub retry_after_seconds: u64,
}

impl Decision {
    fn allowed(retry_after_seconds: u64) -> Self {
        Self {
            allowed: true,
            retry_after_seconds,
        }
    }
    fn denied(retry_after_seconds: u64, _limit: u32) -> Self {
        Self {
            allowed: false,
            retry_after_seconds,
        }
    }
}

/// Client identity used for limiting: the authenticated tenant when known,
/// otherwise the peer address. Anonymous traffic is limited per address so one
/// host cannot spend the whole API budget before authenticating.
pub fn limit_key(tenant: Option<uuid::Uuid>, peer: Option<IpAddr>) -> String {
    match (tenant, peer) {
        (Some(tenant), _) => format!("tenant:{tenant}"),
        (None, Some(peer)) => format!("ip:{peer}"),
        (None, None) => "ip:unknown".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sustained_requests_are_admitted_then_limited() {
        let limiter = RateLimiter::new(RateLimit::new(1.0, 3));
        let start = Instant::now();
        // The burst is admitted.
        for index in 0..3 {
            assert!(
                limiter.check_at("t", start).allowed,
                "burst request {index} should be admitted"
            );
        }
        // The fourth exceeds the burst and must be limited.
        assert!(!limiter.check_at("t", start).allowed);
    }

    #[test]
    fn tokens_refill_over_time() {
        let limiter = RateLimiter::new(RateLimit::new(10.0, 2));
        let start = Instant::now();
        assert!(limiter.check_at("t", start).allowed);
        assert!(limiter.check_at("t", start).allowed);
        assert!(!limiter.check_at("t", start).allowed);
        // 200ms at 10/s refills two tokens.
        let later = start + std::time::Duration::from_millis(200);
        assert!(limiter.check_at("t", later).allowed);
    }

    #[test]
    fn tenants_are_limited_independently() {
        let limiter = RateLimiter::new(RateLimit::new(1.0, 1));
        let now = Instant::now();
        assert!(limiter.check_at("tenant:a", now).allowed);
        assert!(!limiter.check_at("tenant:a", now).allowed);
        assert!(limiter.check_at("tenant:b", now).allowed);
    }

    #[test]
    fn a_zero_rate_denies_instead_of_allowing() {
        let limiter = RateLimiter::new(RateLimit::new(0.0, 10));
        assert!(!limiter.check("t").allowed);
    }

    #[test]
    fn retry_after_is_never_zero_when_denied() {
        let limiter = RateLimiter::new(RateLimit::new(1.0, 1));
        let now = Instant::now();
        assert!(limiter.check_at("t", now).allowed);
        let denied = limiter.check_at("t", now);
        assert!(!denied.allowed);
        assert!(denied.retry_after_seconds >= 1);
    }

    #[test]
    fn a_zero_burst_is_clamped_to_one() {
        assert_eq!(RateLimit::new(1.0, 0).burst, 1);
    }

    #[test]
    fn limit_key_prefers_tenant_over_peer() {
        let tenant = uuid::Uuid::now_v7();
        let peer: IpAddr = "10.0.0.1".parse().expect("ip");
        assert_eq!(
            limit_key(Some(tenant), Some(peer)),
            format!("tenant:{tenant}")
        );
        assert_eq!(limit_key(None, Some(peer)), "ip:10.0.0.1");
        assert_eq!(limit_key(None, None), "ip:unknown");
    }
}
