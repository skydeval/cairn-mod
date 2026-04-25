//! TTL'd LRU caches for DID documents and jti replay detection (§5.2, §5.4).
//!
//! Both caches wrap `lru::LruCache` with expiration checks on access.
//! Entries that are expired when looked up are treated as a miss and
//! evicted, so stale data never influences a decision.
//!
//! Time is read through a `Clock` handle so tests can advance it
//! deterministically — TTL semantics that depend on `Instant::now()`
//! flake under CI scheduling jitter when tests rely on `thread::sleep`
//! to cross small thresholds (§F4 #21). Production passes a
//! `SystemClock`; tests pass `MockClock`.

use std::num::NonZeroUsize;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use lru::LruCache;

use super::did::DidDocument;

/// Source of "now" for the cache TTL checks. Production wires
/// [`SystemClock`]; tests substitute a mock clock with explicit
/// `advance` so TTL behavior is deterministic — no `thread::sleep`,
/// no scheduler-jitter flakes.
pub(crate) trait Clock: Send + Sync {
    /// Current monotonic instant. Implementations must return values
    /// that respect `>=` ordering of real time (or simulated time, in
    /// the mock case) — the cache's expiry check assumes monotonicity.
    fn now(&self) -> Instant;
}

/// Production [`Clock`] backed by [`std::time::Instant::now`].
pub(crate) struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
}

/// Cached DID doc with its expiration. Separate positive/negative TTLs
/// so we can match §5.4 (60s positive, 5s negative) with one structure.
#[derive(Debug, Clone)]
pub(crate) enum CachedResolve {
    Ok(DidDocument),
    /// String because `ResolveError` isn't Clone; we only need a marker
    /// here to short-circuit repeated failures within the negative-TTL
    /// window. The actual re-resolve would re-encounter the real error.
    Err,
}

pub(crate) struct DidDocCache {
    inner: Mutex<LruCache<String, (CachedResolve, Instant)>>,
    positive_ttl: Duration,
    negative_ttl: Duration,
    clock: Arc<dyn Clock>,
}

impl DidDocCache {
    pub fn new(
        size: NonZeroUsize,
        positive_ttl: Duration,
        negative_ttl: Duration,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            inner: Mutex::new(LruCache::new(size)),
            positive_ttl,
            negative_ttl,
            clock,
        }
    }

    pub fn get(&self, did: &str) -> Option<CachedResolve> {
        let mut inner = self.inner.lock().expect("cache mutex poisoned");
        let (cached, expires_at) = inner.get(did)?;
        if self.clock.now() >= *expires_at {
            let key = did.to_owned();
            inner.pop(&key);
            return None;
        }
        Some(cached.clone())
    }

    pub fn insert_ok(&self, did: String, doc: DidDocument) {
        let exp = self.clock.now() + self.positive_ttl;
        self.inner
            .lock()
            .expect("cache mutex poisoned")
            .put(did, (CachedResolve::Ok(doc), exp));
    }

    pub fn insert_err(&self, did: String) {
        let exp = self.clock.now() + self.negative_ttl;
        self.inner
            .lock()
            .expect("cache mutex poisoned")
            .put(did, (CachedResolve::Err, exp));
    }
}

/// Replay cache: `(iss, jti)` → expiration time. On hit with a live
/// entry, the token is a replay. On hit with an expired entry, treat as
/// miss and re-insert.
///
/// Per §5.2: "If an eviction would drop a `jti` whose TTL has not yet
/// expired, that `jti` loses replay protection for the remainder of
/// its TTL" — intentional tradeoff. Call site documents this.
pub(crate) struct JtiCache {
    inner: Mutex<LruCache<(String, String), Instant>>,
    clock: Arc<dyn Clock>,
}

impl JtiCache {
    pub fn new(size: NonZeroUsize, clock: Arc<dyn Clock>) -> Self {
        Self {
            inner: Mutex::new(LruCache::new(size)),
            clock,
        }
    }

    /// Atomically: check whether `(iss, jti)` is in the cache with a
    /// live entry. If so, return `Err(Replay)`. Otherwise insert the
    /// entry with the given `expires_at` and return `Ok(())`.
    ///
    /// Doing check-and-insert in one locked section is load-bearing —
    /// concurrent requests with the same token must both see the
    /// replay on the second.
    pub fn check_and_record(
        &self,
        iss: &str,
        jti: &str,
        expires_at: Instant,
    ) -> Result<(), Replay> {
        let mut inner = self.inner.lock().expect("cache mutex poisoned");
        let key = (iss.to_owned(), jti.to_owned());
        if let Some(existing_exp) = inner.get(&key)
            && self.clock.now() < *existing_exp
        {
            return Err(Replay);
        }
        // Stale entries fall through and are overwritten below.
        // Per-§5.2: LRU eviction may drop a still-live jti to make room;
        // that jti loses replay protection for the remainder of its TTL.
        // Bounded-memory replay protection is the stated tradeoff.
        inner.put(key, expires_at);
        Ok(())
    }
}

/// Returned by the jti cache's `check_and_record` when the
/// `(iss, jti)` pair was already observed inside its TTL (§5.2
/// replay protection). Callers at the auth boundary map this to
/// `AuthError::Replay`.
#[derive(Debug, thiserror::Error)]
#[error("replay detected")]
pub struct Replay;

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn nz(n: usize) -> NonZeroUsize {
        NonZeroUsize::new(n).unwrap()
    }

    /// Test [`Clock`] with explicit, deterministic time control.
    /// Internally tracks ms since `base` (the `Instant` captured at
    /// construction) — `advance` adds to that offset; `now` returns
    /// `base + Duration::from_millis(offset)`.
    ///
    /// AtomicU64 lets a `&MockClock` be advanced from any thread
    /// without taking a lock; cache tests are single-threaded today,
    /// but the pattern matches the production `Send + Sync` contract.
    struct MockClock {
        base: Instant,
        offset_ms: AtomicU64,
    }

    impl MockClock {
        fn new() -> Self {
            Self {
                base: Instant::now(),
                offset_ms: AtomicU64::new(0),
            }
        }

        fn advance(&self, by: Duration) {
            self.offset_ms
                .fetch_add(by.as_millis() as u64, Ordering::Relaxed);
        }
    }

    impl Clock for MockClock {
        fn now(&self) -> Instant {
            self.base + Duration::from_millis(self.offset_ms.load(Ordering::Relaxed))
        }
    }

    #[test]
    fn doc_cache_returns_cached_then_expires() {
        let clock = Arc::new(MockClock::new());
        let cache = DidDocCache::new(
            nz(10),
            Duration::from_millis(50),
            Duration::from_millis(5),
            clock.clone(),
        );
        let doc = DidDocument {
            id: "did:plc:a".into(),
            verification_method: vec![],
        };
        cache.insert_ok("did:plc:a".into(), doc.clone());
        match cache.get("did:plc:a").expect("hit") {
            CachedResolve::Ok(got) => assert_eq!(got.id, "did:plc:a"),
            _ => panic!("expected Ok"),
        }
        // Advance past the positive TTL boundary. Crossing the >=
        // threshold is what the cache's expiry check tests — pick a
        // value strictly greater so the assertion is unambiguous.
        clock.advance(Duration::from_millis(60));
        assert!(cache.get("did:plc:a").is_none(), "must expire");
    }

    #[test]
    fn doc_cache_negative_has_shorter_ttl() {
        let clock = Arc::new(MockClock::new());
        let cache = DidDocCache::new(
            nz(10),
            Duration::from_secs(60),
            Duration::from_millis(5),
            clock.clone(),
        );
        cache.insert_err("did:plc:bad".into());
        assert!(matches!(cache.get("did:plc:bad"), Some(CachedResolve::Err)));
        // Past negative_ttl (5ms) but well under positive_ttl (60s).
        // The mock clock makes the threshold deterministic — the
        // pre-mockclock version slept 15ms, which flaked under CI
        // scheduler jitter when the negative entry's expiry hadn't
        // actually been crossed yet (#21).
        clock.advance(Duration::from_millis(15));
        assert!(cache.get("did:plc:bad").is_none(), "neg entry must expire");
    }

    #[test]
    fn jti_cache_second_use_is_replay() {
        let clock = Arc::new(MockClock::new());
        let cache = JtiCache::new(nz(1000), clock.clone());
        let exp = clock.now() + Duration::from_secs(60);
        cache
            .check_and_record("did:plc:a", "j1", exp)
            .expect("first ok");
        let second = cache.check_and_record("did:plc:a", "j1", exp);
        assert!(second.is_err(), "second use must be replay");
    }

    #[test]
    fn jti_cache_expiry_permits_reuse() {
        let clock = Arc::new(MockClock::new());
        let cache = JtiCache::new(nz(1000), clock.clone());
        let exp = clock.now() + Duration::from_millis(5);
        cache
            .check_and_record("did:plc:a", "j1", exp)
            .expect("first ok");
        clock.advance(Duration::from_millis(20));
        // Stale entry treated as miss — reinsert succeeds.
        cache
            .check_and_record("did:plc:a", "j1", exp)
            .expect("reuse ok post-expiry");
    }

    #[test]
    fn jti_cache_distinguishes_iss() {
        // Same jti, different iss: NOT a replay (replay is per-issuer).
        let clock = Arc::new(MockClock::new());
        let cache = JtiCache::new(nz(1000), clock.clone());
        let exp = clock.now() + Duration::from_secs(60);
        cache.check_and_record("did:plc:a", "same", exp).unwrap();
        cache
            .check_and_record("did:plc:b", "same", exp)
            .expect("different iss, same jti, not replay");
    }
}
