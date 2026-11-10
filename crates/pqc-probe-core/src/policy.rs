//! Target policy for hosted use.
//!
//! A hosted probe connects to hosts chosen by strangers, so it must refuse targets that point
//! inside the operator's network (SSRF) and must not double as a port scanner. The CLI does not
//! apply this policy (your own test bench lives on private addresses); the web service always does.
//!
//! The important rule is **resolve once, check, then connect to that address**. Checking a name and
//! then letting `openssl`/`ssh` resolve it again would let DNS rebinding swap in a private address
//! between the check and the connection. [`prepare_target`] returns a [`Target`] whose `resolved`
//! field carries the checked IPv4 address, and the probe code connects to that.
//!
//! IPv4 only: the probes pass `-4` (broken IPv6 stalls), so only A records are considered.

use crate::Target;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;
use thiserror::Error;

/// Why a target was refused.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum PolicyError {
    #[error("invalid host '{0}': {1}")]
    InvalidHost(String, &'static str),
    #[error("port {0} is not allowed (allowed: {1})")]
    PortNotAllowed(u16, String),
    #[error("'{0}' has no IPv4 address")]
    NoAddress(String),
    #[error("DNS lookup for '{0}' failed: {1}")]
    ResolveFailed(String, String),
    #[error("'{host}' resolves to {ip}, which is not allowed ({reason})")]
    BlockedAddress {
        host: String,
        ip: Ipv4Addr,
        reason: &'static str,
    },
}

/// Ports a hosted instance will probe by default: SSH (22, 2222) and common TLS ports.
pub const DEFAULT_ALLOWED_PORTS: &[u16] = &[22, 443, 465, 636, 853, 993, 995, 2222, 8443];

/// Which targets may be probed.
#[derive(Debug, Clone)]
pub struct Policy {
    /// Allowed destination ports. Empty means any port (1-65535).
    pub allowed_ports: Vec<u16>,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            allowed_ports: DEFAULT_ALLOWED_PORTS.to_vec(),
        }
    }
}

impl Policy {
    /// No port restriction (address blocking still applies).
    pub fn any_port() -> Self {
        Self {
            allowed_ports: Vec::new(),
        }
    }

    pub fn check_port(&self, port: u16) -> Result<(), PolicyError> {
        if port == 0 {
            return Err(PolicyError::PortNotAllowed(0, "1-65535".to_string()));
        }
        if self.allowed_ports.is_empty() || self.allowed_ports.contains(&port) {
            return Ok(());
        }
        let list = self
            .allowed_ports
            .iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        Err(PolicyError::PortNotAllowed(port, list))
    }
}

/// Check that `host` is a plausible DNS name or IPv4 literal. Strict on purpose: ASCII letters,
/// digits, '-' and '.', labels of 1-63 characters that don't start or end with '-', 253 total.
/// IPv6 literals, userinfo, schemes, paths and whitespace all fail here.
pub fn validate_host(host: &str) -> Result<(), PolicyError> {
    let bad = |why: &'static str| PolicyError::InvalidHost(host.to_string(), why);
    if host.is_empty() {
        return Err(bad("empty"));
    }
    if host.len() > 253 {
        return Err(bad("longer than 253 characters"));
    }
    if !host.is_ascii() {
        return Err(bad(
            "must be ASCII (use the punycode form for internationalised names)",
        ));
    }
    let name = host.strip_suffix('.').unwrap_or(host);
    if name.is_empty() {
        return Err(bad("empty"));
    }
    for label in name.split('.') {
        if label.is_empty() {
            return Err(bad("empty label"));
        }
        if label.len() > 63 {
            return Err(bad("label longer than 63 characters"));
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(bad("a label may not start or end with '-'"));
        }
        if !label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return Err(bad("only letters, digits, '-' and '.' are allowed"));
        }
    }
    Ok(())
}

/// (network, prefix length, reason). Anything inside is refused.
const BLOCKED_V4: &[([u8; 4], u8, &str)] = &[
    ([0, 0, 0, 0], 8, "'this network' 0.0.0.0/8"),
    ([10, 0, 0, 0], 8, "private network 10.0.0.0/8"),
    (
        [100, 64, 0, 0],
        10,
        "carrier-grade NAT / shared space 100.64.0.0/10 (includes some cloud metadata)",
    ),
    ([127, 0, 0, 0], 8, "loopback 127.0.0.0/8"),
    (
        [168, 63, 129, 16],
        32,
        "Azure platform endpoint 168.63.129.16",
    ),
    (
        [169, 254, 0, 0],
        16,
        "link-local / cloud metadata 169.254.0.0/16",
    ),
    ([172, 16, 0, 0], 12, "private network 172.16.0.0/12"),
    ([192, 0, 0, 0], 24, "IETF protocol assignments 192.0.0.0/24"),
    ([192, 0, 2, 0], 24, "documentation range 192.0.2.0/24"),
    ([192, 88, 99, 0], 24, "deprecated 6to4 relay 192.88.99.0/24"),
    ([192, 168, 0, 0], 16, "private network 192.168.0.0/16"),
    ([198, 18, 0, 0], 15, "benchmarking range 198.18.0.0/15"),
    ([198, 51, 100, 0], 24, "documentation range 198.51.100.0/24"),
    ([203, 0, 113, 0], 24, "documentation range 203.0.113.0/24"),
    ([224, 0, 0, 0], 4, "multicast 224.0.0.0/4"),
    ([240, 0, 0, 0], 4, "reserved / broadcast 240.0.0.0/4"),
];

/// Why `ip` must not be probed, or None if it is an ordinary public address.
pub fn blocked_reason(ip: Ipv4Addr) -> Option<&'static str> {
    let x = u32::from(ip);
    BLOCKED_V4.iter().find_map(|(net, prefix, reason)| {
        let mask = if *prefix == 0 {
            0
        } else {
            u32::MAX << (32 - *prefix as u32)
        };
        let net = u32::from(Ipv4Addr::from(*net));
        ((x & mask) == (net & mask)).then_some(*reason)
    })
}

/// Apply the policy to an already-resolved name. Pure, so it is easy to test (and to fake DNS).
/// Every address must be allowed: a name with one public and one private record is refused.
pub fn check_resolved(
    host: &str,
    port: u16,
    addrs: &[Ipv4Addr],
    policy: &Policy,
) -> Result<Target, PolicyError> {
    validate_host(host)?;
    policy.check_port(port)?;
    let first = *addrs
        .first()
        .ok_or_else(|| PolicyError::NoAddress(host.to_string()))?;
    for &ip in addrs {
        if let Some(reason) = blocked_reason(ip) {
            return Err(PolicyError::BlockedAddress {
                host: host.to_string(),
                ip,
                reason,
            });
        }
    }
    Ok(Target::new(host, port).with_resolved(first))
}

/// Resolve `host` to its IPv4 addresses. Each attempt has a 5 s limit and a failed or timed-out
/// attempt is tried once more: on networks with broken IPv6 the first lookup of an uncached name
/// can outlive the limit (getaddrinfo also waits for AAAA), while the retry finds the late answer
/// in the resolver's cache.
pub async fn resolve_ipv4(host: &str, port: u16) -> Result<Vec<Ipv4Addr>, PolicyError> {
    retry_lookup(2, || lookup_once(host, port)).await
}

async fn lookup_once(host: &str, port: u16) -> Result<Vec<Ipv4Addr>, PolicyError> {
    let lookup = tokio::net::lookup_host((host, port));
    let found = tokio::time::timeout(Duration::from_secs(5), lookup)
        .await
        .map_err(|_| PolicyError::ResolveFailed(host.to_string(), "timed out after 5s".into()))?
        .map_err(|e| PolicyError::ResolveFailed(host.to_string(), e.to_string()))?;
    let mut v4: Vec<Ipv4Addr> = found
        .filter_map(|a| match a.ip() {
            IpAddr::V4(ip) => Some(ip),
            IpAddr::V6(_) => None,
        })
        .collect();
    v4.sort_unstable();
    v4.dedup();
    Ok(v4)
}

/// Run `f` up to `attempts` times, retrying only when it fails with `ResolveFailed`.
async fn retry_lookup<F, Fut>(attempts: usize, mut f: F) -> Result<Vec<Ipv4Addr>, PolicyError>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<Vec<Ipv4Addr>, PolicyError>>,
{
    let mut last = None;
    for _ in 0..attempts.max(1) {
        match f().await {
            Err(e @ PolicyError::ResolveFailed(..)) => last = Some(e),
            other => return other,
        }
    }
    Err(last.expect("at least one attempt was made"))
}

/// Validate, resolve once, check, and return a [`Target`] pinned to the checked address.
pub async fn prepare_target(host: &str, port: u16, policy: &Policy) -> Result<Target, PolicyError> {
    validate_host(host)?;
    policy.check_port(port)?;
    let addrs = resolve_ipv4(host, port).await?;
    check_resolved(host, port, &addrs, policy)
}

#[cfg(test)]
mod policy_tests {
    use super::*;

    fn ip(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    fn failing() -> Result<Vec<Ipv4Addr>, PolicyError> {
        Err(PolicyError::ResolveFailed(
            "a.test".into(),
            "timed out".into(),
        ))
    }

    #[tokio::test]
    async fn lookup_is_retried_once_after_a_failure() {
        let calls = std::cell::Cell::new(0);
        let r = retry_lookup(2, || {
            calls.set(calls.get() + 1);
            let first = calls.get() == 1;
            async move {
                if first {
                    failing()
                } else {
                    Ok(vec![Ipv4Addr::new(93, 184, 216, 34)])
                }
            }
        })
        .await;
        assert_eq!(r.unwrap(), vec![Ipv4Addr::new(93, 184, 216, 34)]);
        assert_eq!(calls.get(), 2);
    }

    #[tokio::test]
    async fn lookup_gives_up_after_the_last_attempt() {
        let calls = std::cell::Cell::new(0);
        let r = retry_lookup(2, || {
            calls.set(calls.get() + 1);
            async { failing() }
        })
        .await;
        assert!(matches!(r, Err(PolicyError::ResolveFailed(..))));
        assert_eq!(calls.get(), 2);
    }

    #[tokio::test]
    async fn an_empty_answer_is_final_and_not_retried() {
        let calls = std::cell::Cell::new(0);
        let r = retry_lookup(2, || {
            calls.set(calls.get() + 1);
            async { Ok(vec![]) }
        })
        .await;
        assert!(r.unwrap().is_empty());
        assert_eq!(calls.get(), 1);
    }

    #[test]
    fn blocked_ranges_are_blocked_including_boundaries() {
        for s in [
            "0.0.0.0",
            "0.255.255.255",
            "10.0.0.0",
            "10.255.255.255",
            "100.64.0.0",
            "100.100.100.200",
            "100.127.255.255",
            "127.0.0.1",
            "127.255.255.255",
            "168.63.129.16",
            "169.254.0.0",
            "169.254.169.254",
            "169.254.170.2",
            "169.254.255.255",
            "172.16.0.0",
            "172.31.255.255",
            "192.0.0.192",
            "192.0.2.1",
            "192.88.99.1",
            "192.168.0.1",
            "192.168.255.255",
            "198.18.0.1",
            "198.19.255.255",
            "198.51.100.7",
            "203.0.113.9",
            "224.0.0.1",
            "239.255.255.255",
            "240.0.0.1",
            "255.255.255.255",
        ] {
            assert!(blocked_reason(ip(s)).is_some(), "{s} should be blocked");
        }
    }

    #[test]
    fn public_addresses_and_range_neighbours_are_allowed() {
        for s in [
            "1.1.1.1",
            "8.8.8.8",
            "9.255.255.255",
            "11.0.0.0",
            "100.63.255.255",
            "100.128.0.0",
            "104.16.0.1",
            "126.255.255.255",
            "128.0.0.0",
            "140.82.112.3",
            "168.63.129.15",
            "168.63.129.17",
            "169.253.255.255",
            "169.255.0.0",
            "172.15.255.255",
            "172.32.0.0",
            "192.0.1.1",
            "192.167.255.255",
            "192.169.0.0",
            "198.17.255.255",
            "198.20.0.0",
            "223.255.255.255",
        ] {
            assert!(blocked_reason(ip(s)).is_none(), "{s} should be allowed");
        }
    }

    #[test]
    fn host_syntax_accepts_ordinary_names() {
        for h in [
            "github.com",
            "a-b.example.co.uk",
            "example.com.",
            "1.2.3.4",
            "localhost",
            "xn--bcher-kva.example",
        ] {
            assert!(validate_host(h).is_ok(), "{h} should be accepted");
        }
    }

    #[test]
    fn host_syntax_rejects_hostile_input() {
        let long_label = format!("{}.com", "a".repeat(64));
        let long_name = "a.".repeat(130);
        for h in [
            "",
            ".",
            "a..b",
            "-evil.com",
            "evil-.com",
            "-oProxyCommand=x",
            "exa mple.com",
            "user@host.com",
            "host.com/path",
            "http://x.com",
            "[::1]",
            "::1",
            "bücher.de",
            "evil.com;rm",
            "x\n.com",
            "x\0.com",
            long_label.as_str(),
            long_name.as_str(),
        ] {
            assert!(validate_host(h).is_err(), "{h:?} should be rejected");
        }
    }

    #[test]
    fn default_port_allowlist() {
        let p = Policy::default();
        for port in [22, 443, 2222, 8443] {
            assert!(p.check_port(port).is_ok(), "{port}");
        }
        for port in [0, 25, 80, 3306, 6379, 9200] {
            assert!(p.check_port(port).is_err(), "{port}");
        }
    }

    #[test]
    fn any_port_policy_still_rejects_port_zero() {
        let p = Policy::any_port();
        assert!(p.check_port(25).is_ok());
        assert!(p.check_port(0).is_err());
    }

    #[test]
    fn public_target_is_accepted_and_pinned() {
        let t =
            check_resolved("github.com", 443, &[ip("140.82.112.3")], &Policy::default()).unwrap();
        assert_eq!(t.host, "github.com");
        assert_eq!(t.connect_host(), "140.82.112.3");
    }

    #[test]
    fn private_target_is_refused() {
        let err = check_resolved(
            "internal.example",
            443,
            &[ip("10.1.2.3")],
            &Policy::default(),
        )
        .unwrap_err();
        assert!(matches!(err, PolicyError::BlockedAddress { .. }));
    }

    #[test]
    fn mixed_public_and_private_records_are_refused() {
        let addrs = [ip("140.82.112.3"), ip("169.254.169.254")];
        let err = check_resolved("rebind.example", 443, &addrs, &Policy::default()).unwrap_err();
        assert!(matches!(err, PolicyError::BlockedAddress { .. }));
    }

    #[test]
    fn name_with_no_ipv4_address_is_refused() {
        let err = check_resolved("v6only.example", 443, &[], &Policy::default()).unwrap_err();
        assert_eq!(err, PolicyError::NoAddress("v6only.example".to_string()));
    }

    #[test]
    fn numeric_host_tricks_are_caught_after_resolution() {
        // getaddrinfo turns "2130706433" into 127.0.0.1; syntax alone cannot catch that.
        assert!(validate_host("2130706433").is_ok());
        let err =
            check_resolved("2130706433", 443, &[ip("127.0.0.1")], &Policy::default()).unwrap_err();
        assert!(matches!(err, PolicyError::BlockedAddress { .. }));
    }

    #[test]
    fn bad_host_or_port_is_refused_before_any_address_is_used() {
        let public = [ip("1.1.1.1")];
        assert!(matches!(
            check_resolved("-bad.com", 443, &public, &Policy::default()),
            Err(PolicyError::InvalidHost(..))
        ));
        assert!(matches!(
            check_resolved("ok.example", 25, &public, &Policy::default()),
            Err(PolicyError::PortNotAllowed(25, _))
        ));
    }
}
