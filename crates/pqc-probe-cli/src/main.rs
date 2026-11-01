// Replace crates/pqc-probe-cli/src/main.rs with this. Adds experimental and both
// modes, plus a side-by-side diff formatter.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use pqc_probe_core::{probe, probe_dual, DualProbeReport, ProbeMode, ProbeOptions, ProbeReport, Target};
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
    /// Vanilla OpenSSL only — what a stock TLS client sees today.
    Vanilla,
    /// OpenSSL + oqs-provider only — extended codepoint set.
    Experimental,
    /// Both, with a diff section — the Phase 4 lens applied programmatically.
    Both,
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

    let vanilla_openssl = std::env::var("PQC_PROBE_OPENSSL").unwrap_or_else(|_| "openssl".into());
    let oqs_openssl = std::env::var("PQC_PROBE_OPENSSL_OQS").ok();

    match mode {
        Mode::Vanilla => {
            let opts = ProbeOptions {
                mode: ProbeMode::Vanilla,
                timeout: Duration::from_secs(timeout),
                openssl_path: vanilla_openssl,
            };
            let report = probe(&target, &opts).await.context("vanilla probe")?;
            match output {
                Output::Json => println!("{}", serde_json::to_string_pretty(&report)?),
                Output::Human => print_single(&report, "Vanilla"),
            }
        }
        Mode::Experimental => {
            let path = oqs_openssl.context(
                "experimental mode requires PQC_PROBE_OPENSSL_OQS to point at an OpenSSL \
                 binary with oqs-provider activated via openssl.cnf",
            )?;
            let opts = ProbeOptions {
                mode: ProbeMode::Experimental,
                timeout: Duration::from_secs(timeout),
                openssl_path: path,
            };
            let report = probe(&target, &opts).await.context("experimental probe")?;
            match output {
                Output::Json => println!("{}", serde_json::to_string_pretty(&report)?),
                Output::Human => print_single(&report, "Experimental"),
            }
        }
        Mode::Both => {
            let oqs_path = oqs_openssl.context(
                "both mode requires PQC_PROBE_OPENSSL_OQS to be set (in addition to \
                 PQC_PROBE_OPENSSL)",
            )?;
            let vanilla_opts = ProbeOptions {
                mode: ProbeMode::Vanilla,
                timeout: Duration::from_secs(timeout),
                openssl_path: vanilla_openssl,
            };
            let experimental_opts = ProbeOptions {
                mode: ProbeMode::Experimental,
                timeout: Duration::from_secs(timeout),
                openssl_path: oqs_path,
            };
            let dual = probe_dual(&target, &vanilla_opts, &experimental_opts)
                .await
                .context("dual probe")?;
            match output {
                Output::Json => println!("{}", serde_json::to_string_pretty(&dual)?),
                Output::Human => print_dual(&dual),
            }
        }
    }
    Ok(())
}

fn print_single(report: &ProbeReport, label: &str) {
    println!("Target: {}:{}  [{}]", report.target.host, report.target.port, label);
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

fn print_dual(dual: &DualProbeReport) {
    println!("Target: {}:{}", dual.target.host, dual.target.port);
    println!();

    let v_names = dual
        .vanilla
        .as_ref()
        .and_then(|r| r.tls.as_ref())
        .map(|t| negotiated_set(t))
        .unwrap_or_default();
    let e_names = dual
        .experimental
        .as_ref()
        .and_then(|r| r.tls.as_ref())
        .map(|t| negotiated_set(t))
        .unwrap_or_default();

    // Union of offered KEMs across both, in order from either report.
    let offered: Vec<String> = dual
        .vanilla
        .as_ref()
        .and_then(|r| r.tls.as_ref())
        .map(|t| t.kems_tried.iter().map(|k| k.offered.clone()).collect())
        .unwrap_or_default();

    println!("KEMs (vanilla  vs  experimental):");
    println!(
        "  {:<24}  {:<16}  {:<16}",
        "offered", "vanilla", "experimental"
    );
    for kem in &offered {
        let v = if v_names.contains(kem) { "ok" } else { "-" };
        let e = if e_names.contains(kem) { "ok" } else { "-" };
        println!("  {:<24}  {:<16}  {:<16}", kem, v, e);
    }
    println!();

    println!("Diff:");
    if dual.diff.only_experimental.is_empty() && dual.diff.only_vanilla.is_empty() {
        println!("  No TLS algorithms unlocked by oqs-provider on this target.");
        println!("  (See the Phase 4 writeup for why this is a meaningful finding.)");
    } else {
        if !dual.diff.only_experimental.is_empty() {
            println!("  Only via oqs-provider ({}):", dual.diff.only_experimental.len());
            for name in &dual.diff.only_experimental {
                println!("    + {}", name);
            }
        }
        if !dual.diff.only_vanilla.is_empty() {
            println!("  Only via vanilla ({}):", dual.diff.only_vanilla.len());
            for name in &dual.diff.only_vanilla {
                println!("    - {}", name);
            }
        }
    }
}

fn negotiated_set(tls: &pqc_probe_core::TlsReport) -> std::collections::HashSet<String> {
    tls.kems_tried
        .iter()
        .filter(|k| k.handshake_succeeded)
        .filter_map(|k| k.negotiated.clone())
        .collect()
}
