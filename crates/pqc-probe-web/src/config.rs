//! Service configuration, read from `PQC_WEB_*` environment variables.

use pqc_probe_core::policy::DEFAULT_ALLOWED_PORTS;
use pqc_probe_core::{ModeSelection, ProtocolSelection};
use std::net::SocketAddr;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct Config {
    /// Address to listen on. Defaults to loopback: expose it deliberately (behind a reverse
    /// proxy), never by accident.
    pub bind: SocketAddr,
    /// Probes that run at the same time.
    pub max_concurrent: usize,
    /// Jobs that may be queued or running at once; further submissions get 503.
    pub queue_limit: usize,
    /// Hard deadline for one probe once it starts running.
    pub job_timeout: Duration,
    /// How long a finished job (and its report) is kept.
    pub result_ttl: Duration,
    /// Destination ports a probe may target.
    pub allowed_ports: Vec<u16>,
    /// Timeout for each connection a probe makes (not the whole job).
    pub probe_timeout: Duration,
    /// The openssl and ssh binaries probes run.
    pub tools: ToolPaths,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            bind: SocketAddr::from(([127, 0, 0, 1], 8080)),
            max_concurrent: 4,
            queue_limit: 50,
            job_timeout: Duration::from_secs(90),
            result_ttl: Duration::from_secs(3600),
            allowed_ports: DEFAULT_ALLOWED_PORTS.to_vec(),
            probe_timeout: Duration::from_secs(15),
            tools: ToolPaths::default(),
        }
    }
}

impl Config {
    pub fn from_env() -> Result<Self, String> {
        Self::from_lookup(|k| std::env::var(k).ok())
    }

    /// Build a config from any key lookup (the environment in production, a map in tests).
    pub fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Result<Self, String> {
        let mut c = Self::default();
        if let Some(v) = get("PQC_WEB_BIND") {
            c.bind = v.parse().map_err(|_| {
                format!("PQC_WEB_BIND '{v}' is not a socket address like 127.0.0.1:8080")
            })?;
        }
        if let Some(v) = get("PQC_WEB_MAX_CONCURRENT") {
            c.max_concurrent = parse_in_range("PQC_WEB_MAX_CONCURRENT", &v, 1, 64)? as usize;
        }
        if let Some(v) = get("PQC_WEB_QUEUE_LIMIT") {
            c.queue_limit = parse_in_range("PQC_WEB_QUEUE_LIMIT", &v, 1, 10_000)? as usize;
        }
        if let Some(v) = get("PQC_WEB_JOB_TIMEOUT_SECS") {
            c.job_timeout =
                Duration::from_secs(parse_in_range("PQC_WEB_JOB_TIMEOUT_SECS", &v, 1, 600)?);
        }
        if let Some(v) = get("PQC_WEB_RESULT_TTL_SECS") {
            c.result_ttl =
                Duration::from_secs(parse_in_range("PQC_WEB_RESULT_TTL_SECS", &v, 1, 86_400)?);
        }
        if let Some(v) = get("PQC_WEB_ALLOWED_PORTS") {
            let ports: Result<Vec<u16>, _> =
                v.split(',').map(|p| p.trim().parse::<u16>()).collect();
            c.allowed_ports = ports.map_err(|_| {
                format!("PQC_WEB_ALLOWED_PORTS '{v}' must be a comma-separated list of ports")
            })?;
            if c.allowed_ports.contains(&0) {
                return Err("PQC_WEB_ALLOWED_PORTS must not contain port 0".to_string());
            }
        }
        if let Some(v) = get("PQC_WEB_PROBE_TIMEOUT_SECS") {
            c.probe_timeout =
                Duration::from_secs(parse_in_range("PQC_WEB_PROBE_TIMEOUT_SECS", &v, 1, 120)?);
        }
        c.tools = ToolPaths::from_lookup(&get);
        if c.queue_limit < c.max_concurrent {
            return Err(format!(
                "PQC_WEB_QUEUE_LIMIT ({}) must be at least PQC_WEB_MAX_CONCURRENT ({})",
                c.queue_limit, c.max_concurrent
            ));
        }
        Ok(c)
    }
}

/// Where the probe tools live. The experimental (OQS) builds are optional: without them only
/// `vanilla` mode is offered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolPaths {
    pub openssl: String,
    pub openssl_oqs: Option<String>,
    pub ssh: String,
    pub ssh_oqs: Option<String>,
}

impl Default for ToolPaths {
    fn default() -> Self {
        Self {
            openssl: "openssl".to_string(),
            openssl_oqs: None,
            ssh: "ssh".to_string(),
            ssh_oqs: None,
        }
    }
}

impl ToolPaths {
    /// Same variable names as the CLI: PQC_PROBE_OPENSSL, PQC_PROBE_OPENSSL_OQS, PQC_PROBE_SSH,
    /// PQC_PROBE_SSH_OQS. Empty values count as unset.
    pub fn from_lookup(get: &impl Fn(&str) -> Option<String>) -> Self {
        let val = |k: &str| {
            get(k)
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
        };
        Self {
            openssl: val("PQC_PROBE_OPENSSL").unwrap_or_else(|| "openssl".to_string()),
            openssl_oqs: val("PQC_PROBE_OPENSSL_OQS"),
            ssh: val("PQC_PROBE_SSH").unwrap_or_else(|| "ssh".to_string()),
            ssh_oqs: val("PQC_PROBE_SSH_OQS"),
        }
    }

    /// Can the experimental stack run for every protocol in `protocol`?
    pub fn experimental_available(&self, protocol: ProtocolSelection) -> bool {
        let tls = self.openssl_oqs.is_some();
        let ssh = self.ssh_oqs.is_some();
        match protocol {
            ProtocolSelection::Tls => tls,
            ProtocolSelection::Ssh => ssh,
            ProtocolSelection::Both => tls && ssh,
        }
    }

    /// Modes a request for `protocol` may use.
    pub fn available_modes(&self, protocol: ProtocolSelection) -> Vec<&'static str> {
        if self.experimental_available(protocol) {
            vec!["vanilla", "experimental", "both"]
        } else {
            vec!["vanilla"]
        }
    }

    /// The mode a request runs in. No mode asked for means `both` when it is available, else
    /// `vanilla`; an explicit mode that is not available is an error.
    pub fn resolve_mode(
        &self,
        protocol: ProtocolSelection,
        requested: Option<ModeSelection>,
    ) -> Result<ModeSelection, String> {
        let available = self.experimental_available(protocol);
        match requested {
            None => Ok(if available {
                ModeSelection::Both
            } else {
                ModeSelection::Vanilla
            }),
            Some(ModeSelection::Vanilla) => Ok(ModeSelection::Vanilla),
            Some(m) if available => Ok(m),
            Some(m) => {
                let name = match m {
                    ModeSelection::Experimental => "experimental",
                    _ => "both",
                };
                Err(format!(
                    "mode '{name}' is not available on this server for this protocol"
                ))
            }
        }
    }
}

fn parse_in_range(name: &str, v: &str, lo: u64, hi: u64) -> Result<u64, String> {
    let n: u64 = v
        .trim()
        .parse()
        .map_err(|_| format!("{name} '{v}' is not a whole number"))?;
    if (lo..=hi).contains(&n) {
        Ok(n)
    } else {
        Err(format!("{name} must be between {lo} and {hi}, got {n}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn cfg(pairs: &[(&str, &str)]) -> Result<Config, String> {
        let m: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        Config::from_lookup(|k| m.get(k).cloned())
    }

    #[test]
    fn defaults_are_conservative() {
        let c = cfg(&[]).unwrap();
        assert!(c.bind.ip().is_loopback());
        assert_eq!(c.max_concurrent, 4);
        assert_eq!(c.queue_limit, 50);
        assert_eq!(c.job_timeout, Duration::from_secs(90));
        assert_eq!(c.allowed_ports, DEFAULT_ALLOWED_PORTS.to_vec());
    }

    #[test]
    fn overrides_are_applied() {
        let c = cfg(&[
            ("PQC_WEB_BIND", "0.0.0.0:9000"),
            ("PQC_WEB_MAX_CONCURRENT", "2"),
            ("PQC_WEB_QUEUE_LIMIT", "10"),
            ("PQC_WEB_JOB_TIMEOUT_SECS", "30"),
            ("PQC_WEB_ALLOWED_PORTS", "443, 22"),
        ])
        .unwrap();
        assert_eq!(c.bind.port(), 9000);
        assert_eq!(c.max_concurrent, 2);
        assert_eq!(c.queue_limit, 10);
        assert_eq!(c.job_timeout, Duration::from_secs(30));
        assert_eq!(c.allowed_ports, vec![443, 22]);
    }

    #[test]
    fn bad_values_are_rejected_with_the_variable_name() {
        for (k, v) in [
            ("PQC_WEB_BIND", "not-an-address"),
            ("PQC_WEB_MAX_CONCURRENT", "0"),
            ("PQC_WEB_MAX_CONCURRENT", "abc"),
            ("PQC_WEB_JOB_TIMEOUT_SECS", "100000"),
            ("PQC_WEB_ALLOWED_PORTS", "443,x"),
            ("PQC_WEB_ALLOWED_PORTS", "0,443"),
        ] {
            let err = cfg(&[(k, v)]).unwrap_err();
            assert!(err.contains(k), "{err}");
        }
    }

    #[test]
    fn tools_default_to_path_lookup_and_no_experimental_stack() {
        let c = cfg(&[]).unwrap();
        assert_eq!(c.tools, ToolPaths::default());
        assert_eq!(c.probe_timeout, Duration::from_secs(15));
    }

    #[test]
    fn tools_and_probe_timeout_come_from_the_environment() {
        let c = cfg(&[
            ("PQC_PROBE_OPENSSL", "/opt/o/openssl"),
            ("PQC_PROBE_OPENSSL_OQS", "/opt/o/openssl-oqs"),
            ("PQC_PROBE_SSH_OQS", "  "),
            ("PQC_WEB_PROBE_TIMEOUT_SECS", "20"),
        ])
        .unwrap();
        assert_eq!(c.tools.openssl, "/opt/o/openssl");
        assert_eq!(c.tools.openssl_oqs.as_deref(), Some("/opt/o/openssl-oqs"));
        assert_eq!(c.tools.ssh_oqs, None, "blank counts as unset");
        assert_eq!(c.probe_timeout, Duration::from_secs(20));
        assert!(cfg(&[("PQC_WEB_PROBE_TIMEOUT_SECS", "0")]).is_err());
    }

    #[test]
    fn mode_resolution_follows_what_is_installed() {
        let none = ToolPaths::default();
        let tls_only = ToolPaths {
            openssl_oqs: Some("o".into()),
            ..ToolPaths::default()
        };
        let all = ToolPaths {
            openssl_oqs: Some("o".into()),
            ssh_oqs: Some("s".into()),
            ..ToolPaths::default()
        };
        use ModeSelection as M;
        use ProtocolSelection as P;
        assert_eq!(none.resolve_mode(P::Tls, None), Ok(M::Vanilla));
        assert_eq!(tls_only.resolve_mode(P::Tls, None), Ok(M::Both));
        assert_eq!(tls_only.resolve_mode(P::Both, None), Ok(M::Vanilla));
        assert_eq!(all.resolve_mode(P::Both, None), Ok(M::Both));
        assert_eq!(none.resolve_mode(P::Tls, Some(M::Vanilla)), Ok(M::Vanilla));
        assert!(none.resolve_mode(P::Tls, Some(M::Both)).is_err());
        assert!(tls_only
            .resolve_mode(P::Ssh, Some(M::Experimental))
            .is_err());
        assert_eq!(
            all.resolve_mode(P::Ssh, Some(M::Experimental)),
            Ok(M::Experimental)
        );
        assert_eq!(none.available_modes(P::Tls), vec!["vanilla"]);
        assert_eq!(all.available_modes(P::Tls).len(), 3);
    }

    #[test]
    fn queue_must_hold_at_least_the_running_slots() {
        let err = cfg(&[
            ("PQC_WEB_MAX_CONCURRENT", "8"),
            ("PQC_WEB_QUEUE_LIMIT", "4"),
        ])
        .unwrap_err();
        assert!(err.contains("PQC_WEB_QUEUE_LIMIT"));
    }
}
