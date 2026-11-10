//! The two things the service needs from the outside world, as traits so tests can fake them:
//! DNS resolution plus policy ([`Resolver`]) and the probe itself ([`Prober`]).

use crate::config::ToolPaths;
use crate::model::ProbeRequest;
use pqc_probe_core::policy::{prepare_target, Policy, PolicyError};
use pqc_probe_core::report::SideErrors;
use pqc_probe_core::{
    probe, probe_dual, probe_ssh, probe_ssh_dual, ModeSelection, ProbeError, ProbeMode,
    ProbeOptions, Report, ReportTarget, RequestInfo, SshProbeOptions, SshSection, Target,
    TlsSection,
};
use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Everything a probe needs, already validated: targets are pinned to the addresses the policy
/// checked, so the probe cannot be redirected by a second DNS lookup.
#[derive(Debug, Clone)]
pub struct ProbeJob {
    pub request: ProbeRequest,
    /// The mode this job runs in (the request's, or the default resolved by the server).
    pub mode: ModeSelection,
    /// `None` when TLS was not requested.
    pub tls: Option<Target>,
    /// `None` when SSH was not requested.
    pub ssh: Option<Target>,
}

pub trait Prober: Send + Sync + 'static {
    /// Run the probe and build the report. `Err` is a message safe to show to the caller.
    fn probe<'a>(&'a self, job: &'a ProbeJob) -> BoxFuture<'a, Result<Report, String>>;
}

pub trait Resolver: Send + Sync + 'static {
    /// Validate `host`/`port`, resolve once, apply the policy, return a pinned target.
    fn prepare<'a>(
        &'a self,
        host: &'a str,
        port: u16,
        policy: &'a Policy,
    ) -> BoxFuture<'a, Result<Target, PolicyError>>;
}

/// The real resolver: system DNS plus the core policy.
pub struct SystemResolver;

impl Resolver for SystemResolver {
    fn prepare<'a>(
        &'a self,
        host: &'a str,
        port: u16,
        policy: &'a Policy,
    ) -> BoxFuture<'a, Result<Target, PolicyError>> {
        Box::pin(prepare_target(host, port, policy))
    }
}

// ---------------------------------------------------------------------------------------------
// The real prober
// ---------------------------------------------------------------------------------------------

/// Probes with the same core code the CLI uses, shelling out to the configured openssl/ssh.
pub struct CliProber {
    tools: ToolPaths,
    timeout: Duration,
}

impl CliProber {
    pub fn new(tools: ToolPaths, timeout: Duration) -> Self {
        Self { tools, timeout }
    }

    async fn tls(&self, target: &Target, mode: ModeSelection) -> Result<TlsSection, String> {
        let opts = |m: ProbeMode, path: &str| ProbeOptions {
            mode: m,
            timeout: self.timeout,
            openssl_path: path.to_string(),
        };
        let vanilla = opts(ProbeMode::Vanilla, &self.tools.openssl);
        match mode {
            ModeSelection::Vanilla => probe(target, &vanilla)
                .await
                .map(|r| TlsSection::from_single(false, r))
                .map_err(|e| public_error(&e)),
            ModeSelection::Experimental => {
                let path = self.tools.openssl_oqs.as_deref().ok_or_else(unavailable)?;
                probe(target, &opts(ProbeMode::Experimental, path))
                    .await
                    .map(|r| TlsSection::from_single(true, r))
                    .map_err(|e| public_error(&e))
            }
            ModeSelection::Both => {
                let path = self.tools.openssl_oqs.as_deref().ok_or_else(unavailable)?;
                probe_dual(target, &vanilla, &opts(ProbeMode::Experimental, path))
                    .await
                    .map(TlsSection::from_dual)
                    .map_err(|e| public_error(&e))
            }
        }
    }

    async fn ssh(&self, target: &Target, mode: ModeSelection) -> Result<SshSection, String> {
        let opts = |path: &str| SshProbeOptions {
            timeout: self.timeout,
            ssh_path: path.to_string(),
            ..Default::default()
        };
        let vanilla = opts(&self.tools.ssh);
        match mode {
            ModeSelection::Vanilla => probe_ssh(target, &vanilla)
                .await
                .map(|r| SshSection::from_single(false, r))
                .map_err(|e| public_error(&e)),
            ModeSelection::Experimental => {
                let path = self.tools.ssh_oqs.as_deref().ok_or_else(unavailable)?;
                probe_ssh(target, &opts(path))
                    .await
                    .map(|r| SshSection::from_single(true, r))
                    .map_err(|e| public_error(&e))
            }
            ModeSelection::Both => {
                let path = self.tools.ssh_oqs.as_deref().ok_or_else(unavailable)?;
                probe_ssh_dual(target, &vanilla, &opts(path))
                    .await
                    .map(SshSection::from_dual)
                    .map_err(|e| public_error(&e))
            }
        }
    }
}

fn unavailable() -> String {
    "the requested mode is not available on this server".to_string()
}

/// A message that is safe to show to the caller: no paths, no spawn details (those go to the log).
pub fn public_error(e: &ProbeError) -> String {
    match e {
        ProbeError::Timeout => "the probe timed out".to_string(),
        ProbeError::Protocol(m) => m.clone(),
        ProbeError::InvalidTarget(_) => "the target is not valid".to_string(),
        ProbeError::SpawnFailed(io) => {
            tracing::error!(error = %io, "could not start a probe tool");
            "a probe tool could not be started on the server".to_string()
        }
    }
}

impl Prober for CliProber {
    fn probe<'a>(&'a self, job: &'a ProbeJob) -> BoxFuture<'a, Result<Report, String>> {
        Box::pin(async move {
            let (tls, ssh) = tokio::join!(
                async {
                    match &job.tls {
                        Some(t) => Some(self.tls(t, job.mode).await),
                        None => None,
                    }
                },
                async {
                    match &job.ssh {
                        Some(t) => Some(self.ssh(t, job.mode).await),
                        None => None,
                    }
                },
            );
            assemble(job, tls, ssh)
        })
    }
}

fn failed_side(mode: ModeSelection, msg: String) -> SideErrors {
    match mode {
        ModeSelection::Experimental => SideErrors {
            vanilla: None,
            experimental: Some(msg),
        },
        // For Vanilla the only side is vanilla; for Both a whole-protocol failure is reported on
        // both sides.
        ModeSelection::Vanilla => SideErrors {
            vanilla: Some(msg),
            experimental: None,
        },
        ModeSelection::Both => SideErrors {
            vanilla: Some(msg.clone()),
            experimental: Some(msg),
        },
    }
}

/// Combine the per-protocol outcomes into one report. A protocol that failed outright keeps its
/// place in the report with the reason under `errors`; the job as a whole fails only when no
/// requested protocol produced any result.
pub fn assemble(
    job: &ProbeJob,
    tls: Option<Result<TlsSection, String>>,
    ssh: Option<Result<SshSection, String>>,
) -> Result<Report, String> {
    let mut first_error: Option<String> = None;
    let mut any_data = false;

    let tls_section = tls.map(|r| match r {
        Ok(s) => {
            any_data |= s.vanilla.is_some() || s.experimental.is_some();
            if first_error.is_none() {
                first_error = s.errors.vanilla.clone().or(s.errors.experimental.clone());
            }
            s
        }
        Err(msg) => {
            first_error.get_or_insert_with(|| msg.clone());
            TlsSection {
                vanilla: None,
                experimental: None,
                diff: None,
                vanilla_pq_capable: None,
                errors: failed_side(job.mode, msg),
            }
        }
    });
    let ssh_section = ssh.map(|r| match r {
        Ok(s) => {
            any_data |= s.vanilla.is_some() || s.experimental.is_some();
            if first_error.is_none() {
                first_error = s.errors.vanilla.clone().or(s.errors.experimental.clone());
            }
            s
        }
        Err(msg) => {
            first_error.get_or_insert_with(|| msg.clone());
            SshSection {
                vanilla: None,
                experimental: None,
                diff: None,
                errors: failed_side(job.mode, msg),
            }
        }
    });

    if !any_data {
        return Err(first_error.unwrap_or_else(|| "the probe produced no result".to_string()));
    }

    let host = job
        .tls
        .as_ref()
        .or(job.ssh.as_ref())
        .map(|t| t.host.clone())
        .unwrap_or_default();
    Ok(Report::new(
        ReportTarget {
            input: job.request.target.clone(),
            host,
            tls_port: job.tls.as_ref().map(|t| t.port),
            ssh_port: job.ssh.as_ref().map(|t| t.port),
        },
        RequestInfo {
            protocol: job.request.protocol,
            mode: job.mode,
        },
    )
    .with_tls(tls_section)
    .with_ssh(ssh_section))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::job;

    fn tls_with_data() -> TlsSection {
        TlsSection {
            vanilla: Some(pqc_probe_core::TlsReport {
                protocol_version: Some("TLSv1.3".into()),
                cipher: None,
                kems_tried: vec![],
                cert_sig_alg: None,
                peer_sig_alg: None,
                cert_chain: vec![],
                openssl_version: None,
            }),
            experimental: None,
            diff: None,
            vanilla_pq_capable: Some(false),
            errors: SideErrors::default(),
        }
    }

    fn ssh_job() -> ProbeJob {
        let mut j = job("example.test");
        j.request.protocol = pqc_probe_core::ProtocolSelection::Both;
        j.mode = ModeSelection::Vanilla;
        j.ssh = Some(Target::new("example.test", 22));
        j
    }

    #[test]
    fn public_errors_do_not_leak_details() {
        let io = std::io::Error::new(std::io::ErrorKind::NotFound, "/secret/path/openssl");
        let msg = public_error(&ProbeError::SpawnFailed(io));
        assert!(!msg.contains("secret"), "{msg}");
        assert_eq!(public_error(&ProbeError::Timeout), "the probe timed out");
        assert_eq!(
            public_error(&ProbeError::Protocol("no banner".into())),
            "no banner"
        );
    }

    #[test]
    fn one_failed_protocol_keeps_the_other_and_records_the_reason() {
        let j = ssh_job();
        let r = assemble(&j, Some(Ok(tls_with_data())), Some(Err("ssh down".into()))).unwrap();
        assert!(r.tls.is_some());
        let ssh = r.ssh.expect("ssh section stays in the report");
        assert!(ssh.vanilla.is_none() && ssh.experimental.is_none());
        assert_eq!(ssh.errors.vanilla.as_deref(), Some("ssh down"));
    }

    #[test]
    fn all_protocols_failing_fails_the_job_with_the_first_reason() {
        let j = ssh_job();
        let err = assemble(
            &j,
            Some(Err("tls down".into())),
            Some(Err("ssh down".into())),
        )
        .unwrap_err();
        assert_eq!(err, "tls down");
    }

    #[test]
    fn a_section_with_only_side_errors_counts_as_no_result() {
        let mut empty = tls_with_data();
        empty.vanilla = None;
        empty.errors.vanilla = Some("handshake failed".into());
        let j = job("example.test");
        let err = assemble(&j, Some(Ok(empty)), None).unwrap_err();
        assert_eq!(err, "handshake failed");
    }

    #[test]
    fn failure_is_attributed_to_the_side_that_was_requested() {
        assert_eq!(
            failed_side(ModeSelection::Experimental, "x".into()).experimental,
            Some("x".to_string())
        );
        assert!(failed_side(ModeSelection::Experimental, "x".into())
            .vanilla
            .is_none());
        let both = failed_side(ModeSelection::Both, "x".into());
        assert!(both.vanilla.is_some() && both.experimental.is_some());
    }

    #[test]
    fn the_report_records_the_effective_mode() {
        let mut j = job("example.test");
        j.mode = ModeSelection::Vanilla;
        let r = assemble(&j, Some(Ok(tls_with_data())), None).unwrap();
        assert_eq!(r.request.mode, ModeSelection::Vanilla);
        assert_eq!(r.target.tls_port, Some(443));
        assert_eq!(r.target.ssh_port, None);
    }

    #[tokio::test]
    async fn an_unavailable_mode_is_an_error_not_a_panic() {
        let p = CliProber::new(ToolPaths::default(), Duration::from_secs(1));
        let t = Target::new("example.test", 443);
        assert!(p.tls(&t, ModeSelection::Both).await.is_err());
        assert!(p.ssh(&t, ModeSelection::Experimental).await.is_err());
    }
}
