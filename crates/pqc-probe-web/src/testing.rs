//! Fakes for tests: a resolver with a tiny fake DNS and a prober with scripted behavior.

use crate::model::ProbeRequest;
use crate::prober::{BoxFuture, ProbeJob, Prober, Resolver};
use pqc_probe_core::policy::{check_resolved, Policy, PolicyError};
use pqc_probe_core::{ModeSelection, ProtocolSelection, Report, ReportTarget, RequestInfo, Target};
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

/// Fake DNS: `internal.test` is private, `nxdomain.test` has no address, everything else is a
/// public documentation-range address. Policy checks are the real ones.
pub struct FakeResolver;

impl Resolver for FakeResolver {
    fn prepare<'a>(
        &'a self,
        host: &'a str,
        port: u16,
        policy: &'a Policy,
    ) -> BoxFuture<'a, Result<Target, PolicyError>> {
        Box::pin(async move {
            let addrs: Vec<Ipv4Addr> = match host {
                "nxdomain.test" => vec![],
                "internal.test" => vec![Ipv4Addr::new(10, 0, 0, 5)],
                _ => vec![Ipv4Addr::new(93, 184, 216, 34)],
            };
            check_resolved(host, port, &addrs, policy)
        })
    }
}

#[derive(Clone)]
enum Behavior {
    Ok,
    Fail(String),
    Panic,
    Slow(Duration),
}

#[derive(Clone)]
pub struct FakeProber {
    behavior: Behavior,
}

impl FakeProber {
    pub fn ok() -> Arc<dyn Prober> {
        Arc::new(Self {
            behavior: Behavior::Ok,
        })
    }
    pub fn fails(message: &str) -> Arc<dyn Prober> {
        Arc::new(Self {
            behavior: Behavior::Fail(message.to_string()),
        })
    }
    pub fn panics() -> Arc<dyn Prober> {
        Arc::new(Self {
            behavior: Behavior::Panic,
        })
    }
    /// Sleeps for `d` (cancelled by the job deadline or the end of the test), then succeeds.
    pub fn slow(d: Duration) -> Arc<dyn Prober> {
        Arc::new(Self {
            behavior: Behavior::Slow(d),
        })
    }
}

fn report_for(job: &ProbeJob) -> Report {
    Report::new(
        ReportTarget {
            input: job.request.target.clone(),
            host: job
                .tls
                .as_ref()
                .or(job.ssh.as_ref())
                .map(|t| t.host.clone())
                .unwrap_or_default(),
            tls_port: job.tls.as_ref().map(|t| t.port),
            ssh_port: job.ssh.as_ref().map(|t| t.port),
        },
        RequestInfo {
            protocol: job.request.protocol,
            mode: job.mode,
        },
    )
}

impl Prober for FakeProber {
    fn probe<'a>(&'a self, job: &'a ProbeJob) -> BoxFuture<'a, Result<Report, String>> {
        Box::pin(async move {
            match &self.behavior {
                Behavior::Ok => Ok(report_for(job)),
                Behavior::Fail(m) => Err(m.clone()),
                Behavior::Panic => panic!("fake prober panic (expected in tests)"),
                Behavior::Slow(d) => {
                    tokio::time::sleep(*d).await;
                    Ok(report_for(job))
                }
            }
        })
    }
}

/// A TLS-only job against `host:443`, as the API would build it.
pub fn job(host: &str) -> ProbeJob {
    ProbeJob {
        request: ProbeRequest {
            target: host.to_string(),
            protocol: ProtocolSelection::Tls,
            mode: None,
            tls_port: None,
            ssh_port: None,
        },
        mode: ModeSelection::Both,
        tls: Some(Target::new(host, 443)),
        ssh: None,
    }
}
