// Replace crates/pqc-probe-cli/src/main.rs with this.
// Adds --protocol flag (tls | ssh | both), SSH probing, SSH dual-mode diff output.
mod scan;
use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use pqc_probe_core::{
    probe, probe_dual, probe_ssh, probe_ssh_dual, DualProbeReport, DualSshReport, ProbeMode,
    ProbeOptions, ProbeReport, SshProbeOptions, SshReport, Target,
};
use std::time::Duration;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(
    name = "pqc-probe",
    version,
    about = "Detect PQ crypto on TLS and SSH endpoints"
)]
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
        /// Which stack(s) to probe with.
        #[arg(long, value_enum, default_value_t = Mode::Vanilla)]
        mode: Mode,
        /// Which protocol(s) to probe.
        #[arg(long, value_enum, default_value_t = Protocol::Tls)]
        protocol: Protocol,
        /// Output format.
        #[arg(long, value_enum, default_value_t = Output::Human)]
        output: Output,
        /// Per-attempt timeout in seconds.
        #[arg(long, default_value_t = 10)]
        timeout: u64,
        /// Override TLS port (default: parsed from target or 443)
        #[arg(long)]
        tls_port: Option<u16>,
        /// Override SSH port (default: parsed from target or 22)
        #[arg(long)]
        ssh_port: Option<u16>,
    },

    /// Batch-scan a CSV of domains, write results to another CSV.
    /// Input CSV: no header; two columns (rank, domain). Tranco format.
    Scan {
        /// Input CSV file.
        input: std::path::PathBuf,
        /// Output CSV file (append-mode, resumable).
        #[arg(long, default_value = "scan-results.csv")]
        output: std::path::PathBuf,
        /// Concurrent probes.
        #[arg(long, default_value_t = 50)]
        concurrency: usize,
        /// Per-probe timeout in seconds.
        #[arg(long, default_value_t = 5)]
        timeout: u64,
    },
}

#[derive(Clone, Copy, ValueEnum, PartialEq)]
enum Mode {
    Vanilla,
    Experimental,
    Both,
}

#[derive(Clone, Copy, ValueEnum, PartialEq)]
enum Protocol {
    Tls,
    Ssh,
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
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_target(false)
        .init();

    let cli = Cli::parse();
    match cli.command {
        Command::Scan {
            input,
            output,
            concurrency,
            timeout,
        } => {
            let openssl = std::env::var("PQC_PROBE_OPENSSL").unwrap_or_else(|_| "openssl".into());
            scan::run_scan(&input, &output, concurrency, timeout, openssl).await
        }
        Command::Probe {
            target,
            mode,
            protocol,
            output,
            timeout,
            tls_port,
            ssh_port,
        } => run_probe(target, mode, protocol, output, timeout, tls_port, ssh_port).await,
    }
}

async fn run_probe(
    target_str: String,
    mode: Mode,
    protocol: Protocol,
    output: Output,
    timeout: u64,
    tls_port: Option<u16>,
    ssh_port: Option<u16>,
) -> Result<()> {
    let target = Target::parse(&target_str).context("parsing target")?;

    let want_tls = matches!(protocol, Protocol::Tls | Protocol::Both);
    let want_ssh = matches!(protocol, Protocol::Ssh | Protocol::Both);

    let tls_default_port = 443;
    let ssh_default_port = 22;

    if tls_port.is_none() && target.port == ssh_default_port && want_tls && !want_ssh {
        anyhow::bail!(
            "asked for TLS but target port is {} (the SSH default); \
             pass --tls-port to override",
            target.port
        );
    }
    let tls_target = Target {
        host: target.host.clone(),
        port: tls_port.unwrap_or(target.port),
    };
    let ssh_target = Target {
        host: target.host.clone(),
        // When probing both protocols, use the SSH default if the given port looks TLS-y
        port: ssh_port.unwrap_or(
            if protocol == Protocol::Both && target.port == tls_default_port {
                ssh_default_port
            } else {
                target.port
            },
        ),
    };

    let vanilla_openssl = std::env::var("PQC_PROBE_OPENSSL").unwrap_or_else(|_| "openssl".into());
    let oqs_openssl = std::env::var("PQC_PROBE_OPENSSL_OQS").ok();
    let vanilla_ssh = std::env::var("PQC_PROBE_SSH").unwrap_or_else(|_| "ssh".into());
    let oqs_ssh = std::env::var("PQC_PROBE_SSH_OQS").ok();

    let timeout_dur = Duration::from_secs(timeout);

    // ========== Collect results ==========
    let mut tls_single: Option<ProbeReport> = None;
    let mut tls_dual: Option<DualProbeReport> = None;
    let mut ssh_single: Option<SshReport> = None;
    let mut ssh_dual: Option<DualSshReport> = None;

    if want_tls {
        match mode {
            Mode::Vanilla => {
                let opts = ProbeOptions {
                    mode: ProbeMode::Vanilla,
                    timeout: timeout_dur,
                    openssl_path: vanilla_openssl.clone(),
                };
                tls_single = Some(probe(&tls_target, &opts).await.context("TLS probe")?);
            }
            Mode::Experimental => {
                let path = oqs_openssl.clone().context(
                    "experimental TLS mode requires the PQC_PROBE_OPENSSL_OQS env var pointing at \
         an OpenSSL binary with oqs-provider loaded.\n\
         See docs/oqs-setup.md. Quick setup:\n\
           export PQC_PROBE_OPENSSL_OQS=/opt/openssl-3.5/bin/openssl-oqs",
                )?;
                let opts = ProbeOptions {
                    mode: ProbeMode::Experimental,
                    timeout: timeout_dur,
                    openssl_path: path,
                };
                tls_single = Some(probe(&tls_target, &opts).await.context("TLS probe")?);
            }
            Mode::Both => {
                let oqs_path = oqs_openssl.clone().context(
                    "both-mode TLS requires the PQC_PROBE_OPENSSL_OQS env var pointing at \
         an OpenSSL binary with oqs-provider loaded.\n\
         See docs/oqs-setup.md. Quick setup:\n\
           export PQC_PROBE_OPENSSL_OQS=/opt/openssl-3.5/bin/openssl-oqs",
                )?;
                let v = ProbeOptions {
                    mode: ProbeMode::Vanilla,
                    timeout: timeout_dur,
                    openssl_path: vanilla_openssl.clone(),
                };
                let e = ProbeOptions {
                    mode: ProbeMode::Experimental,
                    timeout: timeout_dur,
                    openssl_path: oqs_path,
                };
                tls_dual = Some(
                    probe_dual(&tls_target, &v, &e)
                        .await
                        .context("TLS dual probe")?,
                );
            }
        }
    }

    if want_ssh {
        match mode {
            Mode::Vanilla => {
                let opts = SshProbeOptions {
                    timeout: timeout_dur,
                    ssh_path: vanilla_ssh.clone(),
                };
                ssh_single = Some(probe_ssh(&ssh_target, &opts).await.context("SSH probe")?);
            }
            Mode::Experimental => {
                let path = oqs_ssh.clone().context(
                    "experimental SSH mode requires the PQC_PROBE_SSH_OQS env var pointing at \
         an OQS-OpenSSH ssh client binary.\n\
         See docs/ssh-setup.md. Quick setup:\n\
           export PQC_PROBE_SSH_OQS=/opt/oqs-openssh/bin/ssh",
                )?;
                let opts = SshProbeOptions {
                    timeout: timeout_dur,
                    ssh_path: path,
                };
                ssh_single = Some(probe_ssh(&ssh_target, &opts).await.context("SSH probe")?);
            }
            Mode::Both => {
                let oqs_path = oqs_ssh.clone().context(
                    "both-mode SSH requires the PQC_PROBE_SSH_OQS env var pointing at \
         an OQS-OpenSSH ssh client binary.\n\
         See docs/ssh-setup.md. Quick setup:\n\
           export PQC_PROBE_SSH_OQS=/opt/oqs-openssh/bin/ssh",
                )?;
                let v = SshProbeOptions {
                    timeout: timeout_dur,
                    ssh_path: vanilla_ssh.clone(),
                };
                let e = SshProbeOptions {
                    timeout: timeout_dur,
                    ssh_path: oqs_path,
                };
                ssh_dual = Some(
                    probe_ssh_dual(&ssh_target, &v, &e)
                        .await
                        .context("SSH dual probe")?,
                );
            }
        }
    }

    // ========== Render ==========
    match output {
        Output::Json => {
            // Combine into one JSON object with optional fields.
            let json = serde_json::json!({
                "target": target_str,
                "tls_single": tls_single,
                "tls_dual": tls_dual,
                "ssh_single": ssh_single,
                "ssh_dual": ssh_dual,
            });
            println!("{}", serde_json::to_string_pretty(&json)?);
        }
        Output::Human => {
            println!("Target: {}", target_str);
            if let Some(r) = &tls_single {
                println!();
                print_tls_single(r, mode == Mode::Experimental);
            }
            if let Some(d) = &tls_dual {
                println!();
                print_tls_dual(d);
            }
            if let Some(r) = &ssh_single {
                println!();
                print_ssh_single(r, mode == Mode::Experimental);
            }
            if let Some(d) = &ssh_dual {
                println!();
                print_ssh_dual(d);
            }
        }
    }

    // Nothing to report if both stacks failed: exit non-zero so scripts and CI notice.
    if let Some(d) = &tls_dual {
        if d.vanilla.is_none() && d.experimental.is_none() {
            anyhow::bail!("TLS probe failed on both stacks (see messages above)");
        }
    }
    if let Some(d) = &ssh_dual {
        if d.vanilla.is_none() && d.experimental.is_none() {
            anyhow::bail!("SSH probe failed on both clients (see messages above)");
        }
    }

    Ok(())
}

fn print_tls_single(report: &ProbeReport, experimental: bool) {
    let label = if experimental {
        "TLS (experimental)"
    } else {
        "TLS"
    };
    println!("{}:", label);
    if let Some(tls) = &report.tls {
        if let Some(v) = &tls.protocol_version {
            println!("  Protocol:          {}", v);
        }
        if let Some(v) = &tls.openssl_version {
            println!("  Client OpenSSL:    {}", v);
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
        println!("    {:<24}  {:<24}  handshake", "offered", "negotiated");
        for kem in &tls.kems_tried {
            let neg = kem.negotiated.as_deref().unwrap_or("-");
            let hs = if kem.handshake_succeeded {
                "ok"
            } else {
                "fail"
            };
            println!("    {:<24}  {:<24}  {}", kem.offered, neg, hs);
        }
        print_cert_chain(&tls.cert_chain);
    }
}

fn print_tls_dual(dual: &DualProbeReport) {
    let v_set = dual
        .vanilla
        .as_ref()
        .and_then(|r| r.tls.as_ref())
        .map(negotiated_set_tls)
        .unwrap_or_default();
    let e_set = dual
        .experimental
        .as_ref()
        .and_then(|r| r.tls.as_ref())
        .map(negotiated_set_tls)
        .unwrap_or_default();

    let offered: Vec<String> = dual
        .vanilla
        .as_ref()
        .and_then(|r| r.tls.as_ref())
        .map(|t| t.kems_tried.iter().map(|k| k.offered.clone()).collect())
        .unwrap_or_default();

    let v_ver = dual
        .vanilla
        .as_ref()
        .and_then(|r| r.tls.as_ref())
        .and_then(|t| t.openssl_version.as_deref());
    let e_ver = dual
        .experimental
        .as_ref()
        .and_then(|r| r.tls.as_ref())
        .and_then(|t| t.openssl_version.as_deref());
    if let Some(e) = &dual.vanilla_error {
        println!("vanilla probe FAILED: {}", e);
    }
    if let Some(e) = &dual.experimental_error {
        println!("experimental probe FAILED: {}", e);
    }
    println!("Client OpenSSL:");
    println!("  vanilla:      {}", v_ver.unwrap_or("unknown"));
    println!("  experimental: {}", e_ver.unwrap_or("unknown"));
    println!();
    println!("TLS KEMs (vanilla  vs  experimental):");
    println!(
        "  {:<24}  {:<16}  {:<16}",
        "offered", "vanilla", "experimental"
    );
    for kem in &offered {
        let v = if v_set.contains(kem) { "ok" } else { "-" };
        let e = if e_set.contains(kem) { "ok" } else { "-" };
        println!("  {:<24}  {:<16}  {:<16}", kem, v, e);
    }
    println!();
    println!("TLS diff:");
    if dual.vanilla.is_none() || dual.experimental.is_none() {
        println!("  Not available: one or both TLS probes failed (see above).");
    } else if dual.diff.only_experimental.is_empty() && dual.diff.only_vanilla.is_empty() {
        println!("  No TLS algorithms unlocked by oqs-provider on this target.");
    } else {
        if !dual.diff.only_experimental.is_empty() {
            println!(
                "  Only via oqs-provider ({}):",
                dual.diff.only_experimental.len()
            );
            for n in &dual.diff.only_experimental {
                println!("    + {}", n);
            }
        }
        if !dual.diff.only_vanilla.is_empty() {
            println!("  Only via vanilla ({}):", dual.diff.only_vanilla.len());
            for n in &dual.diff.only_vanilla {
                println!("    - {}", n);
            }
        }
    }
    let chain_src = dual
        .vanilla
        .as_ref()
        .and_then(|r| r.tls.as_ref())
        .filter(|t| !t.cert_chain.is_empty())
        .or_else(|| dual.experimental.as_ref().and_then(|r| r.tls.as_ref()));
    if let Some(t) = chain_src {
        print_cert_chain(&t.cert_chain);
    }
}

fn print_ssh_single(report: &SshReport, experimental: bool) {
    let label = if experimental {
        "SSH (experimental)"
    } else {
        "SSH"
    };
    println!("{}:", label);
    if let Some(v) = &report.server_version {
        println!("  Server version:    {}", v);
    }
    if let Some(v) = &report.client_version {
        println!("  Client version:    {}", v);
    }
    let real_offer_count = report
        .server_offered_kex
        .iter()
        .filter(|k| !is_ssh_protocol_marker(k))
        .count();
    println!("  Server offered KEX ({}):", real_offer_count);
    for k in &report.server_offered_kex {
        if is_ssh_protocol_marker(k) {
            continue;
        }
        let can = if report.client_can_negotiate.contains(k) {
            "✓"
        } else {
            " "
        };
        println!("    {} {}", can, k);
    }
    println!();
    println!(
        "  Client can negotiate ({}):",
        report.client_can_negotiate.len()
    );
    for k in &report.client_can_negotiate {
        println!("    + {}", k);
    }
}

fn print_ssh_dual(dual: &DualSshReport) {
    let server_offered: Vec<String> = dual
        .vanilla
        .as_ref()
        .map(|r| r.server_offered_kex.clone())
        .or_else(|| {
            dual.experimental
                .as_ref()
                .map(|r| r.server_offered_kex.clone())
        })
        .unwrap_or_default();

    let v_set: std::collections::HashSet<String> = dual
        .vanilla
        .as_ref()
        .map(|r| r.client_can_negotiate.iter().cloned().collect())
        .unwrap_or_default();
    let e_set: std::collections::HashSet<String> = dual
        .experimental
        .as_ref()
        .map(|r| r.client_can_negotiate.iter().cloned().collect())
        .unwrap_or_default();

    if let Some(v) = dual.vanilla.as_ref().and_then(|r| r.server_version.clone()) {
        println!("SSH server version: {}", v);
    }

    let v_ssh = dual
        .vanilla
        .as_ref()
        .and_then(|r| r.client_version.as_deref());
    let e_ssh = dual
        .experimental
        .as_ref()
        .and_then(|r| r.client_version.as_deref());
    if let Some(e) = &dual.vanilla_error {
        println!("mainline ssh probe FAILED: {}", e);
    }
    if let Some(e) = &dual.experimental_error {
        println!("OQS-OpenSSH probe FAILED: {}", e);
    }
    println!("SSH clients:");
    println!("  mainline ssh: {}", v_ssh.unwrap_or("unknown"));
    println!("  OQS-OpenSSH:  {}", e_ssh.unwrap_or("unknown"));
    println!();
    println!("SSH KEX (server offer × client support):");
    println!(
        "  {:<40}  {:<16}  {:<16}",
        "server offers", "mainline ssh", "OQS-OpenSSH"
    );
    for k in &server_offered {
        if is_ssh_protocol_marker(k) {
            continue;
        }
        let v = if v_set.contains(k) { "ok" } else { "-" };
        let e = if e_set.contains(k) { "ok" } else { "-" };
        println!("  {:<40}  {:<16}  {:<16}", k, v, e);
    }

    println!();
    println!("SSH diff:");
    if dual.vanilla.is_none() || dual.experimental.is_none() {
        println!("  Not available: one or both SSH probes failed (see above).");
    } else if dual.diff.only_experimental.is_empty() && dual.diff.only_vanilla.is_empty() {
        println!("  Mainline ssh and OQS-OpenSSH negotiate identically on this target.");
    } else {
        if !dual.diff.only_experimental.is_empty() {
            println!(
                "  Only via OQS-OpenSSH ({}):",
                dual.diff.only_experimental.len()
            );
            for n in &dual.diff.only_experimental {
                match dual.diff.mainline_since.get(n) {
                    Some(v) => println!("    + {}  (also in stock OpenSSH >= {})", n, v),
                    None => println!("    + {}  (OQS-only)", n),
                }
            }
            let newer = dual.diff.mainline_since.len();
            let needed = dual
                .diff
                .only_experimental
                .iter()
                .filter_map(|n| pqc_probe_core::mainline_kex_since(n))
                .max();
            if let (true, Some((maj, min))) = (newer > 0, needed) {
                println!(
                    "    {} of {} are in stock OpenSSH >= {}.{}: upgrading ssh closes that part of the gap without OQS.",
                    newer,
                    dual.diff.only_experimental.len(),
                    maj,
                    min
                );
            }
        }
        if !dual.diff.only_vanilla.is_empty() {
            println!(
                "  Only via mainline ssh ({}):",
                dual.diff.only_vanilla.len()
            );
            for n in &dual.diff.only_vanilla {
                println!("    - {}", n);
            }
        }
    }
}

fn print_cert_chain(chain: &[pqc_probe_core::CertInfo]) {
    if chain.is_empty() {
        return;
    }
    println!();
    println!("  Cert chain ({} certs):", chain.len());
    let last = chain.len() - 1;
    for (i, c) in chain.iter().enumerate() {
        let role = if i == 0 && c.self_signed {
            "leaf, self-signed"
        } else if i == 0 {
            "leaf"
        } else if c.self_signed {
            "root"
        } else if i == last {
            "top of sent chain"
        } else {
            "intermediate"
        };
        let pq = if c.post_quantum { "  [PQ]" } else { "" };
        println!("    depth {} ({}): {}{}", c.depth, role, c.subject, pq);
        if let Some(s) = &c.signature_algorithm {
            println!("      sig alg:   {}", s);
        }
        match (&c.public_key_type, c.public_key_bits) {
            (Some(t), Some(b)) => println!("      key:       {} ({} bit)", t, b),
            (Some(t), None) => println!("      key:       {}", t),
            _ => {}
        }
        if let (Some(nb), Some(na)) = (&c.not_before, &c.not_after) {
            println!("      validity:  {} -> {}", nb, na);
        }
        println!("      issuer:    {}", c.issuer);
    }

    let pq_count = chain.iter().filter(|c| c.post_quantum).count();
    println!();
    if pq_count == 0 {
        println!(
            "  Chain PQ status: all {} certs use classical signatures and keys.",
            chain.len()
        );
    } else if pq_count == chain.len() {
        println!(
            "  Chain PQ status: all {} certs are post-quantum.",
            chain.len()
        );
    } else {
        let classical: Vec<String> = chain
            .iter()
            .filter(|c| !c.post_quantum)
            .map(|c| c.depth.to_string())
            .collect();
        println!(
            "  Chain PQ status: {} of {} certs are post-quantum; classical at depth {}.",
            pq_count,
            chain.len(),
            classical.join(", ")
        );
    }
    if let Some(top) = chain.last() {
        if !top.self_signed {
            println!(
                "  Note: server did not send the root; chain ends at depth {}, issued by: {}",
                top.depth, top.issuer
            );
        }
    }
}

fn negotiated_set_tls(tls: &pqc_probe_core::TlsReport) -> std::collections::HashSet<String> {
    tls.kems_tried
        .iter()
        .filter(|k| k.handshake_succeeded)
        .filter_map(|k| k.negotiated.clone())
        .collect()
}

/// Protocol-extension pseudo-algorithms that shouldn't be counted as KEX methods.
/// Hidden from human output; kept in the raw JSON for completeness.
fn is_ssh_protocol_marker(name: &str) -> bool {
    name.starts_with("kex-strict-") || name.starts_with("ext-info-")
}

#[cfg(test)]
mod cli_tests {
    use super::*;

    #[test]
    fn marker_detection() {
        assert!(is_ssh_protocol_marker("kex-strict-s-v00@openssh.com"));
        assert!(is_ssh_protocol_marker("kex-strict-c-v00@openssh.com"));
        assert!(is_ssh_protocol_marker("ext-info-s"));
        assert!(!is_ssh_protocol_marker("curve25519-sha256"));
        assert!(!is_ssh_protocol_marker("mlkem768x25519-sha256"));
        assert!(!is_ssh_protocol_marker(
            "sntrup761x25519-sha512@openssh.com"
        ));
    }
}
