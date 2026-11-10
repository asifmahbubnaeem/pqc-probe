//! The two things the service needs from the outside world, as traits so tests can fake them:
//! DNS resolution plus policy ([`Resolver`]) and the probe itself ([`Prober`]).

use crate::model::ProbeRequest;
use pqc_probe_core::policy::{prepare_target, Policy, PolicyError};
use pqc_probe_core::{Report, Target};
use std::future::Future;
use std::pin::Pin;

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Everything a probe needs, already validated: targets are pinned to the addresses the policy
/// checked, so the probe cannot be redirected by a second DNS lookup.
#[derive(Debug, Clone)]
pub struct ProbeJob {
    pub request: ProbeRequest,
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

/// Placeholder until the real prober is wired in (next step): every job fails with a clear
/// message instead of pretending to probe.
pub struct NotWiredProber;

impl Prober for NotWiredProber {
    fn probe<'a>(&'a self, _job: &'a ProbeJob) -> BoxFuture<'a, Result<Report, String>> {
        Box::pin(async { Err("probing is not wired into the web service yet".to_string()) })
    }
}
