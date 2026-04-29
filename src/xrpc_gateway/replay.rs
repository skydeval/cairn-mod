//! In-memory replay cache for inbound XRPC gateway JWTs (#94,
//! v1.7).
//!
//! Deduplicates `(iss, jti)` over a configurable TTL window. Per-
//! process state; cairn-mod restarts clear the cache. Safe for
//! single-instance deployments (v1.7's deployment model). Multi-
//! instance replay coordination is enterprise-tier per §18.
//!
//! Sibling to the crate-internal `JtiCache` in
//! [`crate::auth::cache`] (which serves the existing
//! `AuthContext`'s outbound + admin-XRPC path); this
//! cache has independent TTL, separate state, and a different
//! security domain. The fork is intentional per §A8.1 — see #93's
//! locked architecture decisions.
//!
//! # Why `std::sync::Mutex` not `tokio::sync::Mutex`
//!
//! Cache operations are synchronous and short — lock / sweep /
//! check / insert / release is microseconds. A `tokio::sync::Mutex`
//! buys nothing here (no async work happens under the lock) and
//! introduces the `clippy::await_holding_lock` hazard. Sync mutex
//! is correct.
//!
//! # Why lazy eviction
//!
//! Background-task sweep would add complexity for no operational
//! gain at v1.7 scale. The cache grows to roughly
//! `peak_unique_jtis_per_TTL_window` entries — bounded by the
//! rate of authentic requests an operator allows. If a cache
//! grows unboundedly in practice, that's a signal of pathological
//! caller behavior that should be investigated rather than masked
//! by a sweep loop.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Outcome of a replay-cache check. The error variant carries
/// no inner data: callers (the replay middleware) translate to
/// the wire envelope independently.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayCheck {
    /// `(iss, jti)` is novel; the cache has now recorded it.
    Novel,
    /// `(iss, jti)` was already seen within the TTL window.
    Replay,
}

/// In-memory dedup cache for inbound JWT `(iss, jti)` tuples.
///
/// Keying on the tuple namespaces per-issuer: two PDSes minting
/// identical `jti` strings by coincidence don't conflict.
pub struct XrpcReplayCache {
    inner: Mutex<HashMap<(String, String), Instant>>,
    ttl: Duration,
    /// Wall-clock-now source. Production uses [`Self::new`]
    /// (`Instant::now`); tests inject a deterministic clock via
    /// [`Self::with_clock`] to advance time without
    /// `tokio::time::sleep`.
    clock: Arc<dyn Fn() -> Instant + Send + Sync>,
}

impl XrpcReplayCache {
    /// Production constructor. The TTL should be at least
    /// `clock_skew_tolerance + 60` seconds (the JWT TTL bsky-PDS
    /// mints) so the cache outlives any token cairn-mod accepts —
    /// the [`crate::xrpc_gateway::config::XrpcGatewayConfig`]
    /// resolver enforces this minimum at config-load.
    pub fn new(ttl: Duration) -> Self {
        Self::with_clock(ttl, Arc::new(Instant::now))
    }

    /// Test-friendly constructor with a deterministic clock.
    /// Tests pass a closure returning a controlled `Instant` so
    /// TTL expiry / lazy eviction can be exercised without wall-
    /// clock dependencies. `pub(crate)` rather than `#[cfg(test)]`
    /// because the production [`Self::new`] delegates to it
    /// (avoiding two parallel constructor bodies).
    pub(crate) fn with_clock(ttl: Duration, clock: Arc<dyn Fn() -> Instant + Send + Sync>) -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            ttl,
            clock,
        }
    }

    /// Check `(iss, jti)` against the cache. On novel, insert
    /// and return [`ReplayCheck::Novel`]. On replay (already
    /// in cache within TTL), return [`ReplayCheck::Replay`].
    ///
    /// Lazy eviction: drops expired entries on every call. The
    /// sweep is bounded by current cache size; for v1.7's scale,
    /// well under a millisecond.
    pub fn check_and_insert(&self, iss: &str, jti: &str) -> ReplayCheck {
        let now = (self.clock)();
        let mut guard = self.inner.lock().unwrap();
        guard.retain(|_, expiry| *expiry > now);
        let key = (iss.to_string(), jti.to_string());
        if guard.contains_key(&key) {
            return ReplayCheck::Replay;
        }
        guard.insert(key, now + self.ttl);
        ReplayCheck::Novel
    }

    /// Test-only inspection of cache size after operations.
    #[cfg(test)]
    pub(crate) fn size(&self) -> usize {
        self.inner.lock().unwrap().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// Mutable test clock. Holds a base `Instant` and an offset
    /// in milliseconds; the closure passed to
    /// [`XrpcReplayCache::with_clock`] adds the offset to the
    /// base. Tests advance the offset to simulate elapsed time.
    struct TestClock {
        base: Instant,
        offset_ms: AtomicU64,
    }

    impl TestClock {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                base: Instant::now(),
                offset_ms: AtomicU64::new(0),
            })
        }

        fn advance_ms(&self, delta: u64) {
            self.offset_ms.fetch_add(delta, Ordering::SeqCst);
        }

        fn closure(self: &Arc<Self>) -> Arc<dyn Fn() -> Instant + Send + Sync> {
            let me = Arc::clone(self);
            Arc::new(move || me.base + Duration::from_millis(me.offset_ms.load(Ordering::SeqCst)))
        }
    }

    #[test]
    fn novel_pair_returns_novel_then_replay() {
        let cache = XrpcReplayCache::new(Duration::from_secs(90));
        assert_eq!(
            cache.check_and_insert("did:plc:a", "jti-1"),
            ReplayCheck::Novel
        );
        assert_eq!(
            cache.check_and_insert("did:plc:a", "jti-1"),
            ReplayCheck::Replay
        );
    }

    #[test]
    fn different_iss_same_jti_both_accepted() {
        // (iss, jti) tuple namespacing: two PDSes minting
        // identical jti strings shouldn't conflict.
        let cache = XrpcReplayCache::new(Duration::from_secs(90));
        assert_eq!(
            cache.check_and_insert("did:plc:a", "shared-jti"),
            ReplayCheck::Novel
        );
        assert_eq!(
            cache.check_and_insert("did:plc:b", "shared-jti"),
            ReplayCheck::Novel
        );
    }

    #[test]
    fn ttl_expiry_clears_entry() {
        let clock = TestClock::new();
        let cache = XrpcReplayCache::with_clock(Duration::from_secs(60), clock.closure());
        assert_eq!(
            cache.check_and_insert("did:plc:a", "jti-1"),
            ReplayCheck::Novel
        );
        // Advance past the TTL window.
        clock.advance_ms(61_000);
        assert_eq!(
            cache.check_and_insert("did:plc:a", "jti-1"),
            ReplayCheck::Novel,
            "expired entry should accept the same (iss, jti) again"
        );
    }

    #[test]
    fn lazy_eviction_drops_expired_entries() {
        let clock = TestClock::new();
        let cache = XrpcReplayCache::with_clock(Duration::from_secs(30), clock.closure());

        // Insert 5 entries.
        for i in 0..5 {
            cache.check_and_insert("did:plc:a", &format!("jti-{i}"));
        }
        assert_eq!(cache.size(), 5);

        // Advance past TTL; insert one more. The eviction sweep
        // should drop the 5 expired entries before inserting.
        clock.advance_ms(31_000);
        cache.check_and_insert("did:plc:a", "jti-fresh");
        assert_eq!(
            cache.size(),
            1,
            "expired entries dropped; only the fresh one remains"
        );
    }

    #[test]
    fn entry_within_ttl_window_is_replay() {
        let clock = TestClock::new();
        let cache = XrpcReplayCache::with_clock(Duration::from_secs(60), clock.closure());
        cache.check_and_insert("did:plc:a", "jti-1");
        // Advance NOT past TTL.
        clock.advance_ms(50_000);
        assert_eq!(
            cache.check_and_insert("did:plc:a", "jti-1"),
            ReplayCheck::Replay,
            "still within TTL window — replay"
        );
    }
}
