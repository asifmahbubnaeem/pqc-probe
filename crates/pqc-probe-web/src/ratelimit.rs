//! Per-client limits: a token bucket (burst plus steady rate), a cap on probes in flight and a
//! daily budget, all keyed by client address. Also works out which address a request came from.
//!
//! IPv6 clients are keyed by their /64, since a single subscriber usually controls a whole /64.
//! Time is passed in by the caller so tests do not need to sleep.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

const DAY: Duration = Duration::from_secs(24 * 60 * 60);
/// Clients tracked at once; beyond this, new clients are refused until old entries expire.
const MAX_TRACKED: usize = 10_000;

#[derive(Debug, Clone)]
pub struct RateLimits {
    /// Requests a client may make back to back.
    pub burst: u32,
    /// Steady refill rate.
    pub per_minute: u32,
    /// Probes of one client that may be queued or running at once.
    pub max_inflight: u32,
    /// Probes per client in any 24 hours.
    pub per_day: u32,
    /// A repeat request for the same target within this time gets the earlier job back instead
    /// of probing again (0 turns this off).
    pub target_cooldown: Duration,
    /// Reverse proxies whose `X-Forwarded-For` header is believed.
    pub trusted_proxies: Vec<IpAddr>,
}

impl Default for RateLimits {
    fn default() -> Self {
        Self {
            burst: 5,
            per_minute: 6,
            max_inflight: 2,
            per_day: 60,
            target_cooldown: Duration::from_secs(60),
            trusted_proxies: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Denied {
    TooFast {
        retry_after: u64,
    },
    TooManyInFlight,
    DailyLimit {
        retry_after: u64,
    },
    /// The table of tracked clients is full.
    Crowded,
}

impl Denied {
    pub fn retry_after(&self) -> u64 {
        match self {
            Self::TooFast { retry_after } | Self::DailyLimit { retry_after } => *retry_after,
            Self::TooManyInFlight => 10,
            Self::Crowded => 60,
        }
    }

    pub fn message(&self) -> &'static str {
        match self {
            Self::TooFast { .. } => "too many requests from your address; slow down",
            Self::TooManyInFlight => "you already have the maximum number of probes running",
            Self::DailyLimit { .. } => "the daily probe limit for your address has been reached",
            Self::Crowded => "the service is tracking too many clients right now",
        }
    }
}

struct IpState {
    tokens: f64,
    last: Instant,
    inflight: u32,
    day_start: Instant,
    day_count: u32,
}

pub struct IpLimiter {
    limits: RateLimits,
    max_tracked: usize,
    state: Mutex<HashMap<IpAddr, IpState>>,
}

/// Holds one in-flight slot for a client; the slot is freed when this is dropped.
pub struct InflightGuard {
    limiter: Arc<IpLimiter>,
    key: IpAddr,
}

impl Drop for InflightGuard {
    fn drop(&mut self) {
        self.limiter.release(self.key);
    }
}

/// The key a client is tracked under: IPv4 as is, IPv6 reduced to its /64.
pub fn bucket_key(ip: IpAddr) -> IpAddr {
    match ip.to_canonical() {
        IpAddr::V4(v4) => IpAddr::V4(v4),
        IpAddr::V6(v6) => IpAddr::V6(Ipv6Addr::from(u128::from(v6) & (!0u128 << 64))),
    }
}

impl IpLimiter {
    pub fn new(limits: RateLimits) -> Arc<Self> {
        Self::with_capacity(limits, MAX_TRACKED)
    }

    pub fn with_capacity(limits: RateLimits, max_tracked: usize) -> Arc<Self> {
        Arc::new(Self {
            limits,
            max_tracked: max_tracked.max(1),
            state: Mutex::new(HashMap::new()),
        })
    }

    fn lock(&self) -> MutexGuard<'_, HashMap<IpAddr, IpState>> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn limits(&self) -> &RateLimits {
        &self.limits
    }

    /// Admit one probe from `ip`, or say why not. A denial costs the client nothing.
    pub fn try_start(self: &Arc<Self>, ip: IpAddr, now: Instant) -> Result<InflightGuard, Denied> {
        let key = bucket_key(ip);
        let l = &self.limits;
        let mut map = self.lock();
        if !map.contains_key(&key) && map.len() >= self.max_tracked {
            prune_locked(&mut map, now);
            if map.len() >= self.max_tracked {
                return Err(Denied::Crowded);
            }
        }
        let burst = f64::from(l.burst);
        let rate = f64::from(l.per_minute.max(1)) / 60.0;
        let st = map.entry(key).or_insert(IpState {
            tokens: burst,
            last: now,
            inflight: 0,
            day_start: now,
            day_count: 0,
        });

        let elapsed = now.saturating_duration_since(st.last).as_secs_f64();
        st.tokens = (st.tokens + elapsed * rate).min(burst);
        st.last = now;
        if now.saturating_duration_since(st.day_start) >= DAY {
            st.day_start = now;
            st.day_count = 0;
        }

        if st.day_count >= l.per_day {
            let left = DAY.saturating_sub(now.saturating_duration_since(st.day_start));
            return Err(Denied::DailyLimit {
                retry_after: left.as_secs().max(1),
            });
        }
        if st.inflight >= l.max_inflight {
            return Err(Denied::TooManyInFlight);
        }
        if st.tokens < 1.0 {
            let wait = ((1.0 - st.tokens) / rate).ceil() as u64;
            return Err(Denied::TooFast {
                retry_after: wait.max(1),
            });
        }
        st.tokens -= 1.0;
        st.day_count += 1;
        st.inflight += 1;
        Ok(InflightGuard {
            limiter: Arc::clone(self),
            key,
        })
    }

    fn release(&self, key: IpAddr) {
        if let Some(st) = self.lock().get_mut(&key) {
            st.inflight = st.inflight.saturating_sub(1);
        }
    }

    /// Forget clients with nothing running whose daily window has ended. Returns how many.
    pub fn prune(&self, now: Instant) -> usize {
        let mut map = self.lock();
        let before = map.len();
        prune_locked(&mut map, now);
        before - map.len()
    }

    pub fn tracked(&self) -> usize {
        self.lock().len()
    }

    pub fn spawn_pruner(self: &Arc<Self>) {
        let limiter = Arc::clone(self);
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(300));
            loop {
                tick.tick().await;
                limiter.prune(Instant::now());
            }
        });
    }
}

fn prune_locked(map: &mut HashMap<IpAddr, IpState>, now: Instant) {
    map.retain(|_, st| st.inflight > 0 || now.saturating_duration_since(st.day_start) < DAY);
}

/// The address a request really came from. `X-Forwarded-For` is believed only when the direct
/// peer is a configured proxy, and then read from the right: the first address that is not itself
/// a trusted proxy is the client. An unparseable header is ignored entirely.
pub fn client_ip(peer: IpAddr, forwarded_for: Option<&str>, trusted: &[IpAddr]) -> IpAddr {
    let peer = peer.to_canonical();
    if !trusted.contains(&peer) {
        return peer;
    }
    let Some(header) = forwarded_for else {
        return peer;
    };
    for part in header.rsplit(',') {
        let Ok(ip) = part.trim().parse::<IpAddr>() else {
            return peer;
        };
        let ip = ip.to_canonical();
        if !trusted.contains(&ip) {
            return ip;
        }
    }
    peer
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn limits(burst: u32, per_minute: u32, max_inflight: u32, per_day: u32) -> RateLimits {
        RateLimits {
            burst,
            per_minute,
            max_inflight,
            per_day,
            ..RateLimits::default()
        }
    }

    #[test]
    fn burst_then_steady_rate() {
        let l = IpLimiter::new(limits(2, 6, 100, 1000)); // one token per 10 s
        let t0 = Instant::now();
        let a = ip("198.51.100.1");
        drop(l.try_start(a, t0).unwrap());
        drop(l.try_start(a, t0).unwrap());
        match l.try_start(a, t0) {
            Err(Denied::TooFast { retry_after }) => assert!((10..=11).contains(&retry_after)),
            other => panic!("expected TooFast, got {:?}", other.err()),
        }
        assert!(l.try_start(a, t0 + Duration::from_secs(11)).is_ok());
    }

    #[test]
    fn refill_never_exceeds_the_burst() {
        let l = IpLimiter::new(limits(2, 6, 100, 1000));
        let t0 = Instant::now();
        let a = ip("198.51.100.1");
        drop(l.try_start(a, t0).unwrap());
        let later = t0 + Duration::from_secs(3600);
        drop(l.try_start(a, later).unwrap());
        drop(l.try_start(a, later).unwrap());
        assert!(matches!(l.try_start(a, later), Err(Denied::TooFast { .. })));
    }

    #[test]
    fn clients_are_independent() {
        let l = IpLimiter::new(limits(1, 6, 100, 1000));
        let t0 = Instant::now();
        drop(l.try_start(ip("198.51.100.1"), t0).unwrap());
        assert!(l.try_start(ip("198.51.100.1"), t0).is_err());
        assert!(l.try_start(ip("198.51.100.2"), t0).is_ok());
    }

    #[test]
    fn in_flight_slots_are_released_when_the_guard_drops() {
        let l = IpLimiter::new(limits(100, 6000, 2, 1000));
        let t0 = Instant::now();
        let a = ip("198.51.100.1");
        let g1 = l.try_start(a, t0).unwrap();
        let _g2 = l.try_start(a, t0).unwrap();
        assert_eq!(l.try_start(a, t0).err(), Some(Denied::TooManyInFlight));
        drop(g1);
        assert!(l.try_start(a, t0).is_ok());
    }

    #[test]
    fn a_denial_does_not_spend_a_token() {
        let l = IpLimiter::new(limits(2, 6, 1, 1000));
        let t0 = Instant::now();
        let a = ip("198.51.100.1");
        let g = l.try_start(a, t0).unwrap(); // 1 token left
        for _ in 0..5 {
            assert_eq!(l.try_start(a, t0).err(), Some(Denied::TooManyInFlight));
        }
        drop(g);
        assert!(
            l.try_start(a, t0).is_ok(),
            "the second token must still be there"
        );
    }

    #[test]
    fn daily_budget_and_reset() {
        let l = IpLimiter::new(limits(100, 6000, 100, 3));
        let t0 = Instant::now();
        let a = ip("198.51.100.1");
        for _ in 0..3 {
            drop(l.try_start(a, t0).unwrap());
        }
        match l.try_start(a, t0 + Duration::from_secs(60)) {
            Err(Denied::DailyLimit { retry_after }) => assert!(retry_after > 80_000),
            other => panic!("expected DailyLimit, got {:?}", other.err()),
        }
        assert!(l.try_start(a, t0 + DAY + Duration::from_secs(1)).is_ok());
    }

    #[test]
    fn ipv6_clients_share_a_slash_64_and_mapped_v4_equals_v4() {
        assert_eq!(
            bucket_key(ip("2001:db8:1:2::1")),
            bucket_key(ip("2001:db8:1:2:ffff::9"))
        );
        assert_ne!(
            bucket_key(ip("2001:db8:1:2::1")),
            bucket_key(ip("2001:db8:1:3::1"))
        );
        assert_eq!(bucket_key(ip("::ffff:198.51.100.7")), ip("198.51.100.7"));
        let l = IpLimiter::new(limits(1, 6, 100, 1000));
        let t0 = Instant::now();
        drop(l.try_start(ip("2001:db8:1:2::1"), t0).unwrap());
        assert!(l.try_start(ip("2001:db8:1:2::2"), t0).is_err());
    }

    #[test]
    fn prune_forgets_idle_clients_but_not_busy_ones() {
        let l = IpLimiter::new(limits(5, 6, 5, 1000));
        let t0 = Instant::now();
        let _busy = l.try_start(ip("198.51.100.1"), t0).unwrap();
        drop(l.try_start(ip("198.51.100.2"), t0).unwrap());
        assert_eq!(
            l.prune(t0 + Duration::from_secs(10)),
            0,
            "day window still open"
        );
        assert_eq!(l.prune(t0 + DAY + Duration::from_secs(1)), 1);
        assert_eq!(l.tracked(), 1);
    }

    #[test]
    fn a_full_table_refuses_new_clients_and_recovers_after_pruning() {
        let l = IpLimiter::with_capacity(limits(5, 6, 5, 1000), 2);
        let t0 = Instant::now();
        drop(l.try_start(ip("198.51.100.1"), t0).unwrap());
        drop(l.try_start(ip("198.51.100.2"), t0).unwrap());
        assert_eq!(
            l.try_start(ip("198.51.100.3"), t0).err(),
            Some(Denied::Crowded)
        );
        // Known clients are unaffected.
        assert!(l.try_start(ip("198.51.100.1"), t0).is_ok());
        assert!(l
            .try_start(ip("198.51.100.3"), t0 + DAY + Duration::from_secs(1))
            .is_ok());
    }

    #[test]
    fn forwarded_for_is_ignored_unless_the_peer_is_a_trusted_proxy() {
        let proxy = ip("10.0.0.1");
        let trusted = [proxy];
        let hdr = Some("203.0.113.9");
        assert_eq!(
            client_ip(ip("198.51.100.5"), hdr, &trusted),
            ip("198.51.100.5")
        );
        assert_eq!(client_ip(proxy, hdr, &trusted), ip("203.0.113.9"));
        assert_eq!(client_ip(proxy, None, &trusted), proxy);
    }

    #[test]
    fn forwarded_for_is_read_from_the_right() {
        let trusted = [ip("10.0.0.1"), ip("10.0.0.2")];
        // The client claimed to be 1.1.1.1; the first proxy appended the real address.
        assert_eq!(
            client_ip(
                ip("10.0.0.1"),
                Some("1.1.1.1, 203.0.113.9, 10.0.0.2"),
                &trusted
            ),
            ip("203.0.113.9")
        );
        assert_eq!(
            client_ip(ip("10.0.0.1"), Some("10.0.0.2"), &trusted),
            ip("10.0.0.1")
        );
        assert_eq!(
            client_ip(ip("10.0.0.1"), Some("not-an-ip, 10.0.0.2"), &trusted),
            ip("10.0.0.1"),
            "an unparseable header is ignored"
        );
    }
}
