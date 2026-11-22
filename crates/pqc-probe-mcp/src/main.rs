//! pqc-probe-mcp: an MCP server (stdio) that lets AI agents run pqc-probe.
//!
//! stdout carries the MCP protocol, so every log line goes to stderr.

mod limit;
mod server;
mod summary;
mod target;

use clap::Parser;
use pqc_probe_core::policy::{Policy, DEFAULT_ALLOWED_PORTS};
use pqc_probe_web::config::ToolPaths;
use pqc_probe_web::prober::CliProber;
use rmcp::{transport::stdio, ServiceExt};
use std::time::Duration;

#[derive(Parser, Debug)]
#[command(name = "pqc-probe-mcp", version, about)]
struct Args {
    /// Stock openssl binary.
    #[arg(long, default_value = "openssl")]
    openssl: String,
    /// openssl with oqs-provider configured (enables the experimental TLS mode).
    #[arg(long)]
    openssl_oqs: Option<String>,
    /// Stock ssh binary.
    #[arg(long, default_value = "ssh")]
    ssh: String,
    /// OQS-OpenSSH ssh binary (enables the experimental SSH mode).
    #[arg(long)]
    ssh_oqs: Option<String>,
    /// Ports the agent may probe, comma separated.
    #[arg(long, value_delimiter = ',', default_values_t = DEFAULT_ALLOWED_PORTS.to_vec())]
    allowed_ports: Vec<u16>,
    /// Most probes started in any 60-second window.
    #[arg(long, default_value_t = 10)]
    probes_per_minute: usize,
    /// Timeout for each openssl/ssh command, in seconds.
    #[arg(long, default_value_t = 10)]
    tool_timeout_secs: u64,
    /// Deadline for a whole tool call, in seconds.
    #[arg(long, default_value_t = 90)]
    call_timeout_secs: u64,
    /// Turn OFF the hosted policy: allow private addresses and any port. Only for probing your
    /// own test bench, with an agent that reads nothing you don't control.
    #[arg(long)]
    unrestricted_targets: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "pqc_probe_mcp=info".into()),
        )
        .init();

    let args = Args::parse();
    if args.unrestricted_targets {
        tracing::warn!("--unrestricted-targets: private addresses and all ports are allowed");
    }

    let tools = ToolPaths {
        openssl: args.openssl,
        openssl_oqs: args.openssl_oqs,
        ssh: args.ssh,
        ssh_oqs: args.ssh_oqs,
    };
    let settings = server::Settings {
        policy: Policy {
            allowed_ports: args.allowed_ports,
        },
        unrestricted: args.unrestricted_targets,
        has_experimental_tls: tools.openssl_oqs.is_some(),
        has_experimental_ssh: tools.ssh_oqs.is_some(),
        call_timeout: Duration::from_secs(args.call_timeout_secs),
    };
    let prober = CliProber::new(tools, Duration::from_secs(args.tool_timeout_secs));
    let limiter = limit::Limiter::new(args.probes_per_minute, 1);

    let service = server::ProbeServer::new(prober, limiter, settings)
        .serve(stdio())
        .await?;
    tracing::info!("pqc-probe-mcp ready on stdio");
    service.waiting().await?;
    Ok(())
}
