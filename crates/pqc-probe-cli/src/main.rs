//! pqc-probe CLI.
//!
//! Usage:
//!   pqc-probe probe example.com:443
//!   pqc-probe probe example.com:443 --output json

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use pqc_probe_core::{probe, ProbeMode, ProbeOptions, Target};
use std::time::Duration;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(name = "pqc-probe", version, about = "Detect PQ crypto on TLS and SSH endpoints")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Probe a target for post-quantum algorithm support.
    Probe {
        /// Target in host:port form, e.g. example.com:443
        target: String,
        /// Which stack to probe with.
        #[arg(long, value_enum, default_value_t = Mode::Vanilla)]
        mode: Mode,
        /// Output format.
        #[arg(long, value_enum, default_value_t = Output::Human)]
        output: Output,
        /// Per-attempt timeout in seconds.
        #[arg(long, default_value_t = 10)]
        timeout: u64,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum Mode {
    /// Vanilla OpenSSL — what a stock TLS client sees.
    Vanilla,
    /// OpenSSL + oqs-provider — extended codepoint set (Week 2+).
    Experimental,
}

impl From<Mode> for ProbeMode {
    fn from(m: Mode) -> Self {
        match m {
            Mode::Vanilla => ProbeMode::Vanilla,
            Mode::Experimental => ProbeMode::Experimental,
        }
    }
}

#[derive(Clone, Copy, ValueEnum)]
enum Output {
    Human,
    Json,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with_target(false)
        .init();

    let cli = Cli::parse();
    match cli.command {
        Command::Probe {
            target,
            mode,
            output,
            timeout,
        } => run_probe(target, mode, output, timeout).await,
    }
}

async fn run_probe(target: String, mode: Mode, output: Output, timeout: u64) -> Result<()> {
    let target = Target::parse(&target).context("parsing target")?;
    let opts = ProbeOptions {
        mode: mode.into(),
        timeout: Duration::from_secs(timeout),
        openssl_path: std::env::var("PQC_PROBE_OPENSSL").unwrap_or_else(|_| "openssl".into()),
    };

    let report = probe(&target, &opts).await.context("running probe")?;

    match output {
        Output::Json => {
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        Output::Human => print_human(&report),
    }
    Ok(())
}

fn print_human(report: &pqc_probe_core::ProbeReport) {
    println!("Target: {}:{}", report.target.host, report.target.port);
    if let Some(tls) = &report.tls {
        println!();
        println!("TLS:");
        if let Some(v) = &tls.protocol_version {
            println!("  Protocol:          {}", v);
        }
        if let Some(c) = &tls.cipher {
            println!("  Cipher:            {}", c);
        }
        if let Some(s) = &tls.cert_sig_alg {
            println!("  Cert sig alg:      {}", s);
        }
        if let Some(s) = &tls.peer_sig_alg {
            println!("  Peer sig alg:      {}", s);
        }
        println!();
        println!("  KEMs:");
        println!("    {:<24}  {:<24}  {}", "offered", "negotiated", "handshake");
        for kem in &tls.kems_tried {
            let neg = kem.negotiated.as_deref().unwrap_or("-");
            let hs = if kem.handshake_succeeded { "ok" } else { "fail" };
            println!("    {:<24}  {:<24}  {}", kem.offered, neg, hs);
        }
    }
}
