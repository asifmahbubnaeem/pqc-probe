//! Request and response types for the JSON API.

use pqc_probe_core::{ModeSelection, ProtocolSelection};
use serde::{Deserialize, Serialize};

/// Body of `POST /api/v1/probes`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProbeRequest {
    /// `host` or `host:port`.
    pub target: String,
    #[serde(default = "default_protocol")]
    pub protocol: ProtocolSelection,
    /// Omitted: `both` when the server has the experimental stack, else `vanilla`.
    #[serde(default)]
    pub mode: Option<ModeSelection>,
    /// Overrides the TLS port (default: the port in `target`, else 443).
    #[serde(default)]
    pub tls_port: Option<u16>,
    /// Overrides the SSH port (default 22; the port in `target` is used for SSH only when
    /// `protocol` is `ssh`).
    #[serde(default)]
    pub ssh_port: Option<u16>,
}

fn default_protocol() -> ProtocolSelection {
    ProtocolSelection::Tls
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum JobStatus {
    Queued,
    Running,
    Succeeded,
    Failed,
    TimedOut,
}

impl JobStatus {
    pub fn is_finished(self) -> bool {
        matches!(self, Self::Succeeded | Self::Failed | Self::TimedOut)
    }
}

/// Response of `GET /api/v1/probes/{id}`.
#[derive(Debug, Clone, Serialize)]
pub struct JobView {
    pub id: String,
    pub status: JobStatus,
    /// The target as submitted.
    pub target: String,
    pub created_at: String,
    pub finished_at: Option<String>,
    /// Why the job failed or timed out.
    pub error: Option<String>,
    /// Present once the report is available.
    pub report_url: Option<String>,
}

/// Response of `POST /api/v1/probes` (202).
#[derive(Debug, Clone, Serialize)]
pub struct Created {
    pub id: String,
    pub status: JobStatus,
    pub status_url: String,
    pub report_url: String,
    /// True when an earlier job for the same target (started within the cooldown) is returned
    /// instead of a new probe.
    pub reused: bool,
}

/// 32 lowercase hex characters, as produced by the job store. Anything else cannot be a job id.
pub fn is_valid_job_id(s: &str) -> bool {
    s.len() == 32 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_defaults_and_strictness() {
        let r: ProbeRequest = serde_json::from_str(r#"{"target":"example.com"}"#).unwrap();
        assert_eq!(r.protocol, ProtocolSelection::Tls);
        assert_eq!(r.mode, None);
        assert!(r.tls_port.is_none() && r.ssh_port.is_none());
        assert!(serde_json::from_str::<ProbeRequest>(r#"{"target":"a","extra":1}"#).is_err());
        assert!(
            serde_json::from_str::<ProbeRequest>(r#"{"target":"a","protocol":"ftp"}"#).is_err()
        );
        assert!(serde_json::from_str::<ProbeRequest>(r#"{"protocol":"tls"}"#).is_err());
    }

    #[test]
    fn job_id_shape() {
        assert!(is_valid_job_id("0123456789abcdef0123456789abcdef"));
        assert!(!is_valid_job_id("0123456789ABCDEF0123456789ABCDEF"));
        assert!(!is_valid_job_id("short"));
        assert!(!is_valid_job_id("../../etc/passwd/0123456789abcdef0123"));
        assert!(!is_valid_job_id(""));
    }

    #[test]
    fn status_serializes_in_snake_case() {
        assert_eq!(
            serde_json::to_string(&JobStatus::TimedOut).unwrap(),
            "\"timed_out\""
        );
        assert!(JobStatus::Failed.is_finished() && !JobStatus::Running.is_finished());
    }
}
