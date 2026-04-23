//! TTL'd LRU caches for DID documents and jti replay detection (§5.2, §5.4).
//!
//! Both caches wrap `lru::LruCache` with expiration checks on access.
//! Entries that are expired when looked up are treated as a miss and
//! evicted, so stale data never influences a decision.

use std::num::NonZeroUsize;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use lru::LruCache;

use super::did::DidDocument;

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
}

impl DidDocCache {
    pub fn new(size: NonZeroUsize, positive_ttl: Duration, negative_ttl: Duration) -> Self {
        Self {
            inner: Mutex::new(LruCache::new(size)),
            positive_ttl,
            negative_ttl,
        }
    }

    pub fn get(&self, did: &str) -> Option<CachedResolve> {
        let mut inner = self.inner.lock().expect("cache mutex poisoned");
        let (cached, expires_at) = inner.get(did)?;
        if Instant::now() >= *expires_at {
            let key = did.to_owned();
            inner.pop(&key);
            return None;
        }
        Some(cached.clone())
    }

    pub fn insert_ok(&self, did: String, doc: DidDocument) {
        let exp = Instant::now() + self.positive_ttl;
        self.inner
            .lock()
            .expect("cache mutex poisoned")
            .put(did, (CachedResolve::Ok(doc), exp));
    }

    pub fn insert_err(&self, did: String) {
        let exp = Instant::now() + self.negative_ttl;
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
}

impl JtiCache {
    pub fn new(size: NonZeroUsize) -> Self {
        Self {
            inner: Mutex::new(LruCache::new(size)),
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
        if let Some(existing_exp) = inner.get(&key) {
            if Instant::now() < *existing_exp {
                return Err(Replay);
            }
            // Stale — fall through and overwrite.
        }
        // Per-§5.2: LRU eviction may drop a still-live jti to make room;
        // that jti loses replay protection for the remainder of its TTL.
        // Bounded-memory replay protection is the stated tradeoff.
        inner.put(key, expires_at);
        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
#[error("replay detected")]
pub struct Replay;

#[cfg(test)]
mod tests {
    use super::*;

    fn nz(n: usize) -> NonZeroUsize {
        NonZeroUsize::new(n).unwrap()
    }

    #[test]
    fn doc_cache_returns_cached_then_expires() {
        let cache = DidDocCache::new(nz(10), Duration::from_millis(50), Duration::from_millis(5));
        let doc = DidDocument {
            id: "did:plc:a".into(),
            verification_method: vec![],
        };
        cache.insert_ok("did:plc:a".into(), doc.clone());
        match cache.get("did:plc:a").expect("hit") {
            CachedResolve::Ok(got) => assert_eq!(got.id, "did:plc:a"),
            _ => panic!("expected Ok"),
        }
        std::thread::sleep(Duration::from_millis(60));
        assert!(cache.get("did:plc:a").is_none(), "must expire");
    }

    #[test]
    fn doc_cache_negative_has_shorter_ttl() {
        let cache = DidDocCache::new(nz(10), Duration::from_secs(60), Duration::from_millis(5));
        cache.insert_err("did:plc:bad".into());
        assert!(matches!(cache.get("did:plc:bad"), Some(CachedResolve::Err)));
        std::thread::sleep(Duration::from_millis(15));
        assert!(cache.get("did:plc:bad").is_none(), "neg entry must expire");
    }

    #[test]
    fn jti_cache_second_use_is_replay() {
        let cache = JtiCache::new(nz(1000));
        let exp = Instant::now() + Duration::from_secs(60);
        cache
            .check_and_record("did:plc:a", "j1", exp)
            .expect("first ok");
        let second = cache.check_and_record("did:plc:a", "j1", exp);
        assert!(second.is_err(), "second use must be replay");
    }

    #[test]
    fn jti_cache_expiry_permits_reuse() {
        let cache = JtiCache::new(nz(1000));
        let exp = Instant::now() + Duration::from_millis(5);
        cache
            .check_and_record("did:plc:a", "j1", exp)
            .expect("first ok");
        std::thread::sleep(Duration::from_millis(20));
        // Stale entry treated as miss — reinsert succeeds.
        cache
            .check_and_record("did:plc:a", "j1", exp)
            .expect("reuse ok post-expiry");
    }

    #[test]
    fn jti_cache_distinguishes_iss() {
        // Same jti, different iss: NOT a replay (replay is per-issuer).
        let cache = JtiCache::new(nz(1000));
        let exp = Instant::now() + Duration::from_secs(60);
        cache.check_and_record("did:plc:a", "same", exp).unwrap();
        cache
            .check_and_record("did:plc:b", "same", exp)
            .expect("different iss, same jti, not replay");
    }
}
