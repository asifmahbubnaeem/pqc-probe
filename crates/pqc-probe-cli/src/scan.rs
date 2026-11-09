//! Batch scanner for Phase 6: read a CSV of domains, probe each on :443, write results CSV.
//! Parallel with a configurable concurrency limit. Resumable — skips domains already in output.
//!
//! Save as `crates/pqc-probe-cli/src/scan.rs`.
//! Register in `main.rs` with `mod scan;` and wire the `Scan` subcommand.

use anyhow::{Context, Result};
use pqc_probe_core::{probe, KemResult, ProbeMode, ProbeOptions, Target};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;

/// One input row from the Tranco CSV (rank,domain — no header expected).
#[derive(Debug, Deserialize)]
struct InputRow {
    rank: u64,
    domain: String,
}

/// One output row in the results CSV.
#[derive(Debug, Serialize)]
struct OutputRow {
    rank: u64,
    domain: String,
    status: &'static str,
    tls_version: String,
    cipher: String,
    cert_sig_alg: String,
    peer_sig_alg: String,
    /// Semicolon-separated list of KEMs the server negotiated.
    kems_negotiated: String,
    /// Convenience flag for aggregation.
    has_x25519mlkem768: bool,
    /// Convenience flag: any ML-KEM variant negotiated.
    has_mlkem: bool,
    probe_duration_ms: u64,
    error_msg: String,
}

pub async fn run_scan(
    input: &Path,
    output: &Path,
    concurrency: usize,
    timeout_secs: u64,
    openssl_path: String,
) -> Result<()> {
    // Load list of already-done domains if output exists (resume support).
    let done: HashSet<String> = load_done_domains(output).unwrap_or_default();
    if !done.is_empty() {
        eprintln!("==> Resume: {} domains already done, skipping", done.len());
    }

    // Read input CSV.
    let mut reader = csv::ReaderBuilder::new()
        .has_headers(false)
        .from_path(input)
        .with_context(|| format!("opening input {}", input.display()))?;

    let rows: Vec<InputRow> = reader
        .deserialize::<InputRow>()
        .filter_map(|r| r.ok())
        .filter(|r| !done.contains(&r.domain))
        .collect();

    eprintln!(
        "==> Scanning {} domains with {} concurrent probes",
        rows.len(),
        concurrency
    );

    // Open output in append mode so we can resume cleanly.
    let output_file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(output)
        .with_context(|| format!("opening output {}", output.display()))?;
    let write_header = done.is_empty()
        && std::fs::metadata(output)
            .map(|m| m.len() == 0)
            .unwrap_or(true);
    let mut writer = csv::WriterBuilder::new()
        .has_headers(write_header)
        .from_writer(output_file);

    // Parallel probing with a semaphore.
    let semaphore = Arc::new(Semaphore::new(concurrency));
    let timeout = Duration::from_secs(timeout_secs);
    let openssl_path = Arc::new(openssl_path);

    let mut handles = Vec::with_capacity(rows.len());
    for row in rows {
        let sem = semaphore.clone();
        let openssl_path = openssl_path.clone();
        handles.push(tokio::spawn(async move {
            let _permit = sem.acquire_owned().await.ok()?;
            Some(probe_one(row, timeout, openssl_path.as_str()).await)
        }));
    }

    let mut done_count = 0usize;
    let mut ok_count = 0usize;
    let total = handles.len();

    for h in handles {
        if let Ok(Some(out)) = h.await {
            if out.status == "ok" {
                ok_count += 1;
            }
            writer.serialize(&out).ok();
            writer.flush().ok(); // flush per row so a crash loses at most one domain
            done_count += 1;
            if done_count % 25 == 0 {
                eprintln!("    [{}/{}]  ok={}", done_count, total, ok_count);
            }
        }
    }

    eprintln!(
        "==> Done. {}/{} ok. Results: {}",
        ok_count,
        total,
        output.display()
    );
    Ok(())
}

async fn probe_one(row: InputRow, timeout: Duration, openssl_path: &str) -> OutputRow {
    let started = Instant::now();
    let target = Target::new(&row.domain, 443);
    let opts = ProbeOptions {
        mode: ProbeMode::Vanilla,
        timeout,
        openssl_path: openssl_path.to_string(),
    };

    match probe(&target, &opts).await {
        Ok(report) => {
            let tls = report.tls.as_ref();
            let negotiated: Vec<&KemResult> = tls
                .map(|t| {
                    t.kems_tried
                        .iter()
                        .filter(|k| k.handshake_succeeded)
                        .collect()
                })
                .unwrap_or_default();

            let kems_negotiated: Vec<String> = negotiated
                .iter()
                .filter_map(|k| k.negotiated.clone())
                .collect();

            let has_x25519mlkem768 = kems_negotiated.iter().any(|k| k == "X25519MLKEM768");
            let has_mlkem = kems_negotiated
                .iter()
                .any(|k| k.contains("MLKEM") || k.contains("mlkem") || k.contains("ML-KEM"));

            // probe() returns Ok even when every KEM handshake failed (DNS failure,
            // refused connection, no TLS on :443). Only count it as "ok" if at least
            // one handshake actually completed.
            let status = if negotiated.is_empty() {
                "no_handshake"
            } else {
                "ok"
            };
            let error_msg = if negotiated.is_empty() {
                "no KEM handshake succeeded (unreachable, no TLS, or timeout)".to_string()
            } else {
                String::new()
            };

            OutputRow {
                rank: row.rank,
                domain: row.domain,
                status,
                tls_version: tls
                    .and_then(|t| t.protocol_version.clone())
                    .unwrap_or_default(),
                cipher: tls.and_then(|t| t.cipher.clone()).unwrap_or_default(),
                cert_sig_alg: tls.and_then(|t| t.cert_sig_alg.clone()).unwrap_or_default(),
                peer_sig_alg: tls.and_then(|t| t.peer_sig_alg.clone()).unwrap_or_default(),
                kems_negotiated: kems_negotiated.join(";"),
                has_x25519mlkem768,
                has_mlkem,
                probe_duration_ms: started.elapsed().as_millis() as u64,
                error_msg,
            }
        }
        Err(e) => OutputRow {
            rank: row.rank,
            domain: row.domain,
            status: "error",
            tls_version: String::new(),
            cipher: String::new(),
            cert_sig_alg: String::new(),
            peer_sig_alg: String::new(),
            kems_negotiated: String::new(),
            has_x25519mlkem768: false,
            has_mlkem: false,
            probe_duration_ms: started.elapsed().as_millis() as u64,
            error_msg: format!("{}", e),
        },
    }
}

fn load_done_domains(output: &Path) -> Result<HashSet<String>> {
    if !output.exists() {
        return Ok(HashSet::new());
    }
    let mut r = csv::ReaderBuilder::new()
        .has_headers(true)
        .from_path(output)?;
    let mut done = HashSet::new();
    for rec in r.records().flatten() {
        if let Some(domain) = rec.get(1) {
            done.insert(domain.to_string());
        }
    }
    Ok(done)
}
