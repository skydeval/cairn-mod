//! SSRF protection for outbound DID resolution (did:web).
//!
//! Without in-process filtering, a malicious `did:web:<host>` whose DNS
//! resolves to a private, loopback, or link-local address could read
//! from the metadata endpoint at `169.254.169.254` or from internal
//! infrastructure. Most operator hardening stops there at the network
//! layer, but Cairn is distributed as a crate — other operators install
//! it in environments where outbound filtering may be absent or
//! incomplete. The defense belongs in the library.
//!
//! Strategy: plug into `reqwest::dns::Resolve` so the check runs during
//! the request's own DNS resolution phase. Every IP returned by the
//! system resolver is checked against the block list; if none pass, the
//! request fails before a socket is opened.
//!
//! This also prevents the TOCTOU variant where an attacker's DNS
//! returns two records (one safe, one internal) and the HTTP client
//! picks the wrong one — only safe IPs reach the connection attempt.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use reqwest::dns::{Addrs, Name, Resolve, Resolving};

/// Reject rules for outbound addresses reached via DNS resolution.
///
/// Per §5 threat model, did:web hosts that resolve to any of these
/// categories must fail closed; a legitimate public DID never points at
/// one of these ranges.
#[must_use]
pub fn is_blocked_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_blocked_ipv4(v4),
        IpAddr::V6(v6) => {
            // IPv4-mapped IPv6 (::ffff:a.b.c.d): apply v4 rules to the
            // mapped address. Attackers can encode a private v4 this way.
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_blocked_ipv4(v4);
            }
            is_blocked_ipv6(v6)
        }
    }
}

fn is_blocked_ipv4(v4: Ipv4Addr) -> bool {
    v4.is_loopback()              // 127.0.0.0/8
        || v4.is_private()        // 10/8, 172.16/12, 192.168/16
        || v4.is_link_local()     // 169.254.0.0/16 — includes cloud metadata (169.254.169.254)
        || v4.is_broadcast()      // 255.255.255.255
        || v4.is_documentation()  // 192.0.2, 198.51.100, 203.0.113 — non-routable, could be proxied
        || v4.is_unspecified()    // 0.0.0.0
        || v4.is_multicast()      // 224.0.0.0/4
        || is_cgnat(v4) // 100.64.0.0/10 — carrier-grade NAT, not globally routable
}

/// Carrier-grade NAT range (RFC 6598). Rust's `Ipv4Addr::is_shared` is
/// stable as of 1.76 but exposed only under the unstable feature
/// `ip_extra_stabilized` on some toolchains; the check is two bytes so
/// inlining is fine.
fn is_cgnat(v4: Ipv4Addr) -> bool {
    let [a, b, _, _] = v4.octets();
    a == 100 && (64..=127).contains(&b)
}

fn is_blocked_ipv6(v6: Ipv6Addr) -> bool {
    v6.is_loopback()                          // ::1
        || v6.is_multicast()                  // ff00::/8
        || v6.is_unspecified()                // ::
        || is_ipv6_link_local(v6)             // fe80::/10
        || is_ipv6_unique_local(v6) // fc00::/7 (ULA)
}

fn is_ipv6_link_local(v6: Ipv6Addr) -> bool {
    // fe80::/10 — first 10 bits are 1111111010.
    (v6.segments()[0] & 0xffc0) == 0xfe80
}

fn is_ipv6_unique_local(v6: Ipv6Addr) -> bool {
    // fc00::/7 — first 7 bits are 1111110.
    (v6.segments()[0] & 0xfe00) == 0xfc00
}

/// Error surfaced when every resolved IP for a host is blocked. Kept as
/// a concrete type so the caller can map it to an auth-boundary-friendly
/// generic error without leaking "this host is private" back to clients.
#[derive(Debug, thiserror::Error)]
#[error("SSRF protection rejected all IPs for host: {host}")]
pub struct SsrfRejected {
    /// Host (DNS name) whose resolved IPs were all blocked.
    pub host: String,
}

/// `reqwest::dns::Resolve` wrapper that runs the system resolver (via
/// `tokio::net::lookup_host`) and filters results through [`is_blocked_ip`].
///
/// Returned as `Arc<dyn Resolve>` to satisfy reqwest's builder.
#[derive(Debug, Default)]
pub struct SafeDnsResolver;

impl Resolve for SafeDnsResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let host = name.as_str().to_owned();
        Box::pin(async move {
            // `lookup_host` needs a `host:port`. Port doesn't matter for
            // resolution itself; reqwest's internal caller overrides it.
            let addrs = tokio::net::lookup_host(format!("{host}:0"))
                .await
                .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { Box::new(e) })?;

            let safe: Vec<SocketAddr> = addrs.filter(|sa| !is_blocked_ip(sa.ip())).collect();
            if safe.is_empty() {
                return Err(
                    Box::new(SsrfRejected { host }) as Box<dyn std::error::Error + Send + Sync>
                );
            }
            Ok(Box::new(safe.into_iter()) as Addrs)
        })
    }
}

impl SafeDnsResolver {
    /// Convenience for `ClientBuilder::dns_resolver` which expects an
    /// `Arc<R>` with `R: Resolve + Sized`. Returning `Arc<Self>` rather
    /// than `Arc<dyn Resolve>` satisfies the bound.
    pub fn arc() -> Arc<Self> {
        Arc::new(Self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(s: &str) -> IpAddr {
        IpAddr::V4(s.parse().unwrap())
    }
    fn v6(s: &str) -> IpAddr {
        IpAddr::V6(s.parse().unwrap())
    }

    #[test]
    fn blocks_loopback_v4() {
        assert!(is_blocked_ip(v4("127.0.0.1")));
        assert!(is_blocked_ip(v4("127.255.255.255")));
    }

    #[test]
    fn blocks_private_ranges() {
        assert!(is_blocked_ip(v4("10.0.0.1")));
        assert!(is_blocked_ip(v4("10.255.255.255")));
        assert!(is_blocked_ip(v4("172.16.0.1")));
        assert!(is_blocked_ip(v4("172.31.255.255")));
        assert!(is_blocked_ip(v4("192.168.1.1")));
    }

    #[test]
    fn blocks_link_local_including_metadata() {
        // The specific cloud metadata endpoint that motivates SSRF filtering.
        assert!(is_blocked_ip(v4("169.254.169.254")));
        // Whole link-local range.
        assert!(is_blocked_ip(v4("169.254.0.1")));
        assert!(is_blocked_ip(v4("169.254.255.254")));
    }

    #[test]
    fn blocks_cgnat() {
        assert!(is_blocked_ip(v4("100.64.0.1")));
        assert!(is_blocked_ip(v4("100.127.255.254")));
    }

    #[test]
    fn blocks_broadcast_and_unspecified_and_multicast() {
        assert!(is_blocked_ip(v4("0.0.0.0")));
        assert!(is_blocked_ip(v4("255.255.255.255")));
        assert!(is_blocked_ip(v4("224.0.0.1")));
    }

    #[test]
    fn blocks_ipv6_loopback_link_local_ula_multicast_unspecified() {
        assert!(is_blocked_ip(v6("::1")));
        assert!(is_blocked_ip(v6("::")));
        assert!(is_blocked_ip(v6("fe80::1")));
        assert!(is_blocked_ip(v6("fc00::1"))); // ULA
        assert!(is_blocked_ip(v6("fd00::1"))); // ULA
        assert!(is_blocked_ip(v6("ff02::1"))); // Multicast
    }

    #[test]
    fn blocks_ipv4_mapped_v6() {
        // ::ffff:10.0.0.1 — attacker tries to encode private v4 in v6.
        assert!(is_blocked_ip(v6("::ffff:10.0.0.1")));
        assert!(is_blocked_ip(v6("::ffff:169.254.169.254")));
        assert!(is_blocked_ip(v6("::ffff:127.0.0.1")));
    }

    #[test]
    fn allows_public_addresses() {
        // Representative public IPs.
        assert!(!is_blocked_ip(v4("1.1.1.1")));
        assert!(!is_blocked_ip(v4("8.8.8.8")));
        assert!(!is_blocked_ip(v4("140.82.121.3")));
        // Global-scope IPv6.
        assert!(!is_blocked_ip(v6("2606:4700:4700::1111"))); // Cloudflare
        assert!(!is_blocked_ip(v6("2001:4860:4860::8888"))); // Google
    }
}
