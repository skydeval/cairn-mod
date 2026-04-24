//! Concurrent-subscriber caps (§F4, §12).
//!
//! Two bounded counts:
//!
//! - **Global**: total live subscribers across all clients.
//! - **Per-IP**: live subscribers per client IP, a defense against a single
//!   misbehaving peer exhausting the global budget.
//!
//! A single [`std::sync::Mutex`] is fine — acquisition happens once per
//! connection (a rare event compared to per-message work) and holds for a
//! few tens of nanoseconds. Avoids pulling `dashmap` for the single map we
//! need, and keeps the whole module auditable at a glance.
//!
//! A permit is returned as an RAII guard; dropping it (on connection end
//! or on rejection) releases the slots. If both global and per-IP slots
//! are available, the acquisition is atomic — never leave the counters in
//! a state where one was incremented but the other was rejected.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

/// Concurrent-subscriber limiter. Cheap to clone (`Arc` internally).
#[derive(Debug)]
pub struct Limiter {
    global_cap: usize,
    per_ip_cap: usize,
    inner: Mutex<LimiterInner>,
}

#[derive(Debug, Default)]
struct LimiterInner {
    global: usize,
    per_ip: HashMap<IpAddr, usize>,
}

/// RAII guard for one claimed subscriber slot. Drop releases.
pub struct Permit {
    limiter: Arc<Limiter>,
    ip: IpAddr,
}

impl std::fmt::Debug for Permit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Permit").field("ip", &self.ip).finish()
    }
}

impl Limiter {
    /// Build a `Limiter` with the given §F4 caps. Returned as
    /// `Arc<Self>` because subscribeLabels handlers share one
    /// limiter across all connections.
    pub fn new(global_cap: usize, per_ip_cap: usize) -> Arc<Self> {
        Arc::new(Self {
            global_cap,
            per_ip_cap,
            inner: Mutex::new(LimiterInner::default()),
        })
    }

    /// Try to claim a subscriber slot for `ip`. Returns `None` if either
    /// cap would be exceeded; the counters are untouched on rejection.
    pub fn try_acquire(self: &Arc<Self>, ip: IpAddr) -> Option<Permit> {
        let mut inner = self.inner.lock().expect("limiter mutex poisoned");
        if inner.global >= self.global_cap {
            return None;
        }
        let per_ip = inner.per_ip.get(&ip).copied().unwrap_or(0);
        if per_ip >= self.per_ip_cap {
            return None;
        }
        inner.global += 1;
        *inner.per_ip.entry(ip).or_insert(0) += 1;
        drop(inner);
        Some(Permit {
            limiter: Arc::clone(self),
            ip,
        })
    }

    /// Snapshot for tests and operator debugging. Not load-bearing on a
    /// hot path; recomputed each call.
    pub fn snapshot(&self) -> (usize, usize) {
        let inner = self.inner.lock().expect("limiter mutex poisoned");
        (inner.global, inner.per_ip.len())
    }
}

impl Drop for Permit {
    fn drop(&mut self) {
        let mut inner = self.limiter.inner.lock().expect("limiter mutex poisoned");
        inner.global = inner.global.saturating_sub(1);
        if let Some(c) = inner.per_ip.get_mut(&self.ip) {
            *c = c.saturating_sub(1);
            if *c == 0 {
                inner.per_ip.remove(&self.ip);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(n: u8) -> IpAddr {
        IpAddr::from([127, 0, 0, n])
    }

    #[test]
    fn releases_on_drop_decrements_counters() {
        let l = Limiter::new(10, 10);
        {
            let _p = l.try_acquire(ip(1)).expect("acquire");
            assert_eq!(l.snapshot().0, 1);
        }
        assert_eq!(l.snapshot().0, 0);
    }

    #[test]
    fn global_cap_rejects_excess() {
        let l = Limiter::new(2, 10);
        let _a = l.try_acquire(ip(1)).expect("first");
        let _b = l.try_acquire(ip(2)).expect("second");
        assert!(l.try_acquire(ip(3)).is_none(), "third must be rejected");
    }

    #[test]
    fn per_ip_cap_rejects_excess_from_same_ip() {
        let l = Limiter::new(100, 2);
        let _a = l.try_acquire(ip(1)).expect("first");
        let _b = l.try_acquire(ip(1)).expect("second");
        assert!(
            l.try_acquire(ip(1)).is_none(),
            "third from same ip rejected"
        );
        // Different IP still passes — per-IP isolation.
        let _c = l.try_acquire(ip(2)).expect("different ip ok");
    }

    #[test]
    fn rejection_does_not_increment_counters() {
        let l = Limiter::new(1, 10);
        let _a = l.try_acquire(ip(1)).expect("first");
        assert_eq!(l.snapshot().0, 1);
        let rejected = l.try_acquire(ip(2));
        assert!(rejected.is_none());
        assert_eq!(l.snapshot().0, 1, "rejection must not increment");
    }
}
