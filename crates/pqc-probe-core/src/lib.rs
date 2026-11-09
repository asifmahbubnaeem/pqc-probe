//! pqc-probe-core — core probe logic for detecting post-quantum algorithms
//! on TLS and SSH endpoints.
//!
//! TLS probing shells out to `openssl s_client` (one handshake per candidate
//! group, run in parallel); dual mode diffs vanilla OpenSSL against
//! OpenSSL + oqs-provider. SSH probing lives in [`ssh`].

pub mod ssh;

// Re-export at crate root so pqc-probe-cli can `use pqc_probe_core::{SshReport, ...}`.
pub use ssh::{probe_ssh, probe_ssh_dual, DualSshReport, SshKexDiff, SshProbeOptions, SshReport};

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::time::Duration;
use thiserror::Error;
use tokio::process::Command;

/// A TLS or SSH target.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Target {
    pub host: String,
    pub port: u16,
}

impl Target {
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        Self {
            host: host.into(),
            port,
        }
    }

    /// Parse a target in `host:port` form.
    pub fn parse(s: &str) -> Result<Self, ProbeError> {
        let (host, port) = s
            .rsplit_once(':')
            .ok_or_else(|| ProbeError::InvalidTarget(s.to_string()))?;
        let port = port
            .parse::<u16>()
            .map_err(|_| ProbeError::InvalidTarget(s.to_string()))?;
        Ok(Self::new(host, port))
    }
}

/// Which stack to probe with.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum ProbeMode {
    /// Vanilla OpenSSL — what a stock TLS client sees today.
    Vanilla,
    /// OpenSSL + oqs-provider — the extended codepoint set.
    Experimental,
}

/// Probe options.
#[derive(Debug, Clone)]
pub struct ProbeOptions {
    pub mode: ProbeMode,
    pub timeout: Duration,
    /// Path to the openssl binary. Defaults to "openssl" from $PATH.
    pub openssl_path: String,
}

impl Default for ProbeOptions {
    fn default() -> Self {
        Self {
            mode: ProbeMode::Vanilla,
            timeout: Duration::from_secs(10),
            openssl_path: "openssl".to_string(),
        }
    }
}

/// Full probe report for a target.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeReport {
    pub target: Target,
    pub tls: Option<TlsReport>,
}

/// TLS-side findings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsReport {
    pub protocol_version: Option<String>,
    pub cipher: Option<String>,
    /// Which KEMs the server negotiated when offered. Each entry is "offered → negotiated".
    pub kems_tried: Vec<KemResult>,
    /// Signature algorithm on the server's certificate.
    pub cert_sig_alg: Option<String>,
    /// Signature algorithm used in CertificateVerify (what the server actually signed with).
    pub peer_sig_alg: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KemResult {
    pub offered: String,
    pub negotiated: Option<String>,
    pub handshake_succeeded: bool,
}

#[derive(Debug, Error)]
pub enum ProbeError {
    #[error("invalid target '{0}' — expected host:port")]
    InvalidTarget(String),
    #[error("failed to spawn openssl: {0}")]
    SpawnFailed(#[from] std::io::Error),
    #[error("probe timed out")]
    Timeout,
}

/// Probe a target.
pub async fn probe(target: &Target, opts: &ProbeOptions) -> Result<ProbeReport, ProbeError> {
    let tls = probe_tls(target, opts).await?;
    Ok(ProbeReport {
        target: target.clone(),
        tls: Some(tls),
    })
}

/// Known TLS 1.3 group names worth probing for.
/// Order matters only for stable output; probing happens in parallel.
pub const KEM_CANDIDATES: &[&str] = &[
    // Classical
    "X25519",
    "P-256",
    "P-384",
    "P-521",
    // Hybrid PQ (OpenSSL 3.5+)
    "X25519MLKEM768",
    "SecP256r1MLKEM768",
    "SecP384r1MLKEM1024",
];

async fn probe_tls(target: &Target, opts: &ProbeOptions) -> Result<TlsReport, ProbeError> {
    // Probe each KEM in parallel. For each, run openssl s_client with -groups $KEM
    // and parse the result.
    let mut handles = Vec::with_capacity(KEM_CANDIDATES.len());
    for &kem in KEM_CANDIDATES {
        let target = target.clone();
        let opts = opts.clone();
        let kem_owned = kem.to_string();
        handles.push(tokio::spawn(async move {
            try_kem(&target, &opts, &kem_owned).await
        }));
    }

    let mut kems_tried = Vec::new();
    let mut protocol_version = None;
    let mut cipher = None;
    let mut cert_sig_alg = None;
    let mut peer_sig_alg = None;

    for handle in handles {
        if let Ok(Ok(result)) = handle.await {
            // Capture metadata from the first successful handshake.
            if result.handshake_succeeded {
                protocol_version = protocol_version.or(result.protocol_version);
                cipher = cipher.or(result.cipher);
                cert_sig_alg = cert_sig_alg.or(result.cert_sig_alg);
                peer_sig_alg = peer_sig_alg.or(result.peer_sig_alg);
            }
            kems_tried.push(KemResult {
                offered: result.offered,
                negotiated: result.negotiated,
                handshake_succeeded: result.handshake_succeeded,
            });
        }
    }

    Ok(TlsReport {
        protocol_version,
        cipher,
        kems_tried,
        cert_sig_alg,
        peer_sig_alg,
    })
}

struct KemAttempt {
    offered: String,
    negotiated: Option<String>,
    handshake_succeeded: bool,
    protocol_version: Option<String>,
    cipher: Option<String>,
    cert_sig_alg: Option<String>,
    peer_sig_alg: Option<String>,
}

async fn try_kem(
    target: &Target,
    opts: &ProbeOptions,
    kem: &str,
) -> Result<KemAttempt, ProbeError> {
    let address = format!("{}:{}", target.host, target.port);
    let (stdout, stderr) = run_s_client(
        &opts.openssl_path,
        &[
            "s_client",
            "-4", // force IPv4: broken-IPv6 networks stall ~5s before fallback
            "-connect",
            &address,
            "-tls1_3",
            "-groups",
            kem,
            "-servername",
            &target.host,
        ],
        opts.timeout,
    )
    .await?;

    let combined = format!("{}\n{}", stdout, stderr);

    // Protocol — same label, tolerate 0, 1, 2 or more spaces before the colon.
    let protocol_version = extract_kv(&combined, "Protocol");

    // Cipher — 3.0.x has "Cipher    : X", 3.5.x has "New, TLSv1.3, Cipher is X".
    let cipher_raw =
        extract_kv(&combined, "Cipher").or_else(|| extract_after(&combined, "Cipher is "));

    // Negotiated group — 3.0.x "Server Temp Key:", 3.5.x "Negotiated TLS1.3 group:".
    let server_temp_raw = extract_kv(&combined, "Server Temp Key")
        .or_else(|| extract_kv(&combined, "Peer Temp Key"))
        .or_else(|| extract_kv(&combined, "Negotiated group"))
        .or_else(|| extract_kv(&combined, "Negotiated TLS1.3 group"))
        .or_else(|| extract_kv(&combined, "Negotiated TLS 1.3 group"))
        .filter(|s| s != "<NULL>" && !s.is_empty());

    let peer_sig_alg = extract_kv(&combined, "Peer signature type")
        .or_else(|| extract_kv(&combined, "Peer signing digest"));

    // Handshake succeeded iff we got a real cipher and a TLS 1.3 protocol line.
    let handshake_succeeded = cipher_raw
        .as_deref()
        .map(|c| !c.is_empty() && !c.contains("(NONE)"))
        .unwrap_or(false)
        && protocol_version
            .as_deref()
            .map(|p| p.starts_with("TLSv1.3") || p.starts_with("TLS 1.3"))
            .unwrap_or(false);

    let negotiated = server_temp_raw.as_deref().and_then(normalize_group);
    let cipher = cipher_raw.filter(|c| !c.contains("(NONE)"));

    // Prefer cert chain's `sigalg:` (clean, 3.5.x emits it on every chain line);
    // fall back to body-of-cert "Signature Algorithm:" line (3.0.x behavior).
    let cert_sig_alg = extract_chain_sigalg(&combined).or_else(|| extract_cert_sig_alg(&combined));

    Ok(KemAttempt {
        offered: kem.to_string(),
        negotiated,
        handshake_succeeded,
        protocol_version,
        cipher,
        cert_sig_alg,
        peer_sig_alg,
    })
}

/// Extract value from a "Key: Value" line, tolerating any whitespace around the colon.
fn extract_kv(text: &str, key: &str) -> Option<String> {
    text.lines().find_map(|line| {
        let line = line.trim();
        let (k, v) = line.split_once(':')?;
        if k.trim() == key {
            let v = v.trim();
            if v.is_empty() {
                None
            } else {
                Some(v.to_string())
            }
        } else {
            None
        }
    })
}

/// Extract the token immediately after a marker string, trimmed, up to end of line.
/// Used for openssl 3.5.x's "New, TLSv1.3, Cipher is <X>" format.
fn extract_after(text: &str, marker: &str) -> Option<String> {
    text.lines().find_map(|line| {
        line.split_once(marker)
            .map(|(_, rest)| rest.trim().to_string())
            .filter(|s| !s.is_empty())
    })
}

/// Pull sigalg from cert chain `a:...sigalg: X` lines (openssl 3.5.x).
/// The sigalg may be followed by other info; stop at semicolon.
fn extract_chain_sigalg(text: &str) -> Option<String> {
    text.lines().find_map(|line| {
        line.split_once("sigalg:")
            .map(|(_, after)| {
                let s = after.trim();
                let end = s.find(';').unwrap_or(s.len());
                s[..end].trim().to_string()
            })
            .filter(|s| !s.is_empty())
    })
}

/// Fallback: pull from "Signature Algorithm:" line in cert body (openssl 3.0.x).
fn extract_cert_sig_alg(text: &str) -> Option<String> {
    text.lines().find_map(|line| {
        line.trim_start()
            .strip_prefix("Signature Algorithm:")
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
    })
}

/// Normalize openssl's negotiated-group reporting to a clean algorithm name.
///
/// Examples:
///   "X25519, 253 bits"             -> "X25519"           (3.0.x)
///   "ECDH, prime256v1, 256 bits"   -> "P-256"            (3.0.x)
///   "ECDH, P-384, 384 bits"        -> "P-384"            (3.0.x)
///   "X25519MLKEM768"               -> "X25519MLKEM768"   (3.5.x)
///   "X25519"                       -> "X25519"           (3.5.x)
fn normalize_group(raw: &str) -> Option<String> {
    if raw == "<NULL>" {
        return None;
    }
    let parts: Vec<&str> = raw.split(',').map(|s| s.trim()).collect();
    if parts.is_empty() || parts[0].is_empty() {
        return None;
    }

    let name = if parts[0].eq_ignore_ascii_case("ECDH") && parts.len() >= 2 {
        parts[1]
    } else {
        parts[0]
    };

    let normalized = match name {
        "prime256v1" | "secp256r1" => "P-256",
        "secp384r1" => "P-384",
        "secp521r1" => "P-521",
        other => other,
    };

    Some(normalized.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_target_works() {
        let t = Target::parse("example.com:443").unwrap();
        assert_eq!(t.host, "example.com");
        assert_eq!(t.port, 443);
    }

    #[test]
    fn parse_target_rejects_bad_input() {
        assert!(Target::parse("example.com").is_err());
        assert!(Target::parse("example.com:notaport").is_err());
    }

    // --- 3.0.x format regression ---

    const OSSL_30X_SAMPLE: &str = "\
    Protocol  : TLSv1.3\n\
    Cipher    : TLS_AES_256_GCM_SHA384\n\
    Server Temp Key: X25519, 253 bits\n\
    Peer signature type: ecdsa_secp256r1_sha256\n\
    ";

    #[test]
    fn parses_3_0_x_format() {
        assert_eq!(
            extract_kv(OSSL_30X_SAMPLE, "Protocol"),
            Some("TLSv1.3".to_string())
        );
        assert_eq!(
            extract_kv(OSSL_30X_SAMPLE, "Cipher"),
            Some("TLS_AES_256_GCM_SHA384".to_string())
        );
        assert_eq!(
            extract_kv(OSSL_30X_SAMPLE, "Server Temp Key")
                .as_deref()
                .and_then(normalize_group),
            Some("X25519".to_string())
        );
        assert_eq!(
            extract_kv(OSSL_30X_SAMPLE, "Peer signature type"),
            Some("ecdsa_secp256r1_sha256".to_string())
        );
    }

    // --- 3.5.x format ---

    const OSSL_35X_SAMPLE: &str = "\
    Peer signing digest: SHA256\n\
    Peer signature type: ecdsa_secp256r1_sha256\n\
    Negotiated TLS1.3 group: X25519MLKEM768\n\
    ---\n\
    New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384\n\
    Protocol: TLSv1.3\n\
       a:PKEY: EC, (prime256v1); sigalg: ecdsa-with-SHA256\n\
    ";

    #[test]
    fn parses_3_5_x_format() {
        assert_eq!(
            extract_kv(OSSL_35X_SAMPLE, "Protocol"),
            Some("TLSv1.3".to_string())
        );
        assert_eq!(
            extract_after(OSSL_35X_SAMPLE, "Cipher is "),
            Some("TLS_AES_256_GCM_SHA384".to_string())
        );
        assert_eq!(
            extract_kv(OSSL_35X_SAMPLE, "Negotiated TLS1.3 group")
                .as_deref()
                .and_then(normalize_group),
            Some("X25519MLKEM768".to_string())
        );
        assert_eq!(
            extract_kv(OSSL_35X_SAMPLE, "Peer signature type"),
            Some("ecdsa_secp256r1_sha256".to_string())
        );
        assert_eq!(
            extract_chain_sigalg(OSSL_35X_SAMPLE),
            Some("ecdsa-with-SHA256".to_string())
        );
    }

    // --- normalize_group ---

    #[test]
    fn normalize_group_cases() {
        assert_eq!(
            normalize_group("X25519, 253 bits"),
            Some("X25519".to_string())
        );
        assert_eq!(
            normalize_group("ECDH, prime256v1, 256 bits"),
            Some("P-256".to_string())
        );
        assert_eq!(
            normalize_group("ECDH, P-384, 384 bits"),
            Some("P-384".to_string())
        );
        assert_eq!(
            normalize_group("X25519MLKEM768"),
            Some("X25519MLKEM768".to_string())
        );
        assert_eq!(normalize_group(""), None);
    }

    #[test]
    fn parses_3_5_x_classical_peer_temp_key() {
        let sample = "Protocol: TLSv1.3\n\
                      New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384\n\
                      Peer Temp Key: X25519, 253 bits\n";
        assert_eq!(
            extract_kv(sample, "Peer Temp Key")
                .as_deref()
                .and_then(normalize_group),
            Some("X25519".to_string())
        );
    }

    #[test]
    fn normalize_group_rejects_null_sentinel() {
        assert_eq!(normalize_group("<NULL>"), None);
    }
}

// ---------- Dual-mode probing (vanilla vs oqs-provider) ----------

/// Report that combines two probes of the same target: one via vanilla OpenSSL,
/// one via OpenSSL with oqs-provider loaded. The diff between the two is the
/// actionable output — it says what oqs-provider actually adds to the TLS layer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DualProbeReport {
    pub target: Target,
    pub vanilla: Option<ProbeReport>,
    pub experimental: Option<ProbeReport>,
    pub diff: KemDiff,
}

/// Diff summary across the two probes' negotiated KEM sets.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct KemDiff {
    /// KEMs that negotiated in vanilla but not in experimental.
    pub only_vanilla: Vec<String>,
    /// KEMs that negotiated in experimental but not in vanilla — the interesting case.
    pub only_experimental: Vec<String>,
    /// KEMs that negotiated in both.
    pub in_both: Vec<String>,
}

/// Probe the same target with two openssl stacks in parallel, then diff.
///
/// `vanilla_opts.openssl_path` should point at a plain OpenSSL build.
/// `experimental_opts.openssl_path` should point at an OpenSSL build with
/// oqs-provider activated via `openssl.cnf` (see repo docs/oqs-setup.md).
pub async fn probe_dual(
    target: &Target,
    vanilla_opts: &ProbeOptions,
    experimental_opts: &ProbeOptions,
) -> Result<DualProbeReport, ProbeError> {
    let (vanilla_result, experimental_result) = tokio::join!(
        probe(target, vanilla_opts),
        probe(target, experimental_opts),
    );

    let vanilla = vanilla_result.ok();
    let experimental = experimental_result.ok();

    let diff = compute_diff(vanilla.as_ref(), experimental.as_ref());

    Ok(DualProbeReport {
        target: target.clone(),
        vanilla,
        experimental,
        diff,
    })
}

fn compute_diff(vanilla: Option<&ProbeReport>, experimental: Option<&ProbeReport>) -> KemDiff {
    let v_names = extract_negotiated(vanilla);
    let e_names = extract_negotiated(experimental);

    let only_vanilla: Vec<String> = v_names.difference(&e_names).cloned().collect();
    let only_experimental: Vec<String> = e_names.difference(&v_names).cloned().collect();
    let in_both: Vec<String> = v_names.intersection(&e_names).cloned().collect();

    let mut only_vanilla = only_vanilla;
    let mut only_experimental = only_experimental;
    let mut in_both = in_both;
    only_vanilla.sort();
    only_experimental.sort();
    in_both.sort();

    KemDiff {
        only_vanilla,
        only_experimental,
        in_both,
    }
}

fn extract_negotiated(report: Option<&ProbeReport>) -> HashSet<String> {
    report
        .and_then(|r| r.tls.as_ref())
        .map(|t| {
            t.kems_tried
                .iter()
                .filter(|k| k.handshake_succeeded)
                .filter_map(|k| k.negotiated.clone())
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod dual_tests {
    use super::*;

    fn fake_report(negotiated: &[&str]) -> ProbeReport {
        ProbeReport {
            target: Target::new("example.com", 443),
            tls: Some(TlsReport {
                protocol_version: Some("TLSv1.3".to_string()),
                cipher: Some("TLS_AES_256_GCM_SHA384".to_string()),
                kems_tried: negotiated
                    .iter()
                    .map(|&name| KemResult {
                        offered: name.to_string(),
                        negotiated: Some(name.to_string()),
                        handshake_succeeded: true,
                    })
                    .collect(),
                cert_sig_alg: None,
                peer_sig_alg: None,
            }),
        }
    }

    #[test]
    fn diff_empty_when_identical() {
        let v = fake_report(&["X25519", "P-256"]);
        let e = fake_report(&["X25519", "P-256"]);
        let d = compute_diff(Some(&v), Some(&e));
        assert_eq!(d.in_both, vec!["P-256", "X25519"]);
        assert!(d.only_vanilla.is_empty());
        assert!(d.only_experimental.is_empty());
    }

    #[test]
    fn diff_captures_experimental_additions() {
        let v = fake_report(&["X25519", "P-256"]);
        let e = fake_report(&["X25519", "P-256", "x25519_kyber768"]);
        let d = compute_diff(Some(&v), Some(&e));
        assert_eq!(d.only_experimental, vec!["x25519_kyber768"]);
        assert!(d.only_vanilla.is_empty());
        assert_eq!(d.in_both, vec!["P-256", "X25519"]);
    }

    #[test]
    fn diff_handles_missing_experimental() {
        let v = fake_report(&["X25519"]);
        let d = compute_diff(Some(&v), None);
        assert_eq!(d.in_both, Vec::<String>::new());
        assert_eq!(d.only_vanilla, vec!["X25519"]);
    }
}

// ---------- s_client runner ----------

/// Marker printed at the end of s_client's post-handshake summary (3.0.x and 3.5.x).
/// Every field the parser needs (chain, peer sig, group, cipher, protocol) comes before it.
const SCLIENT_DONE_MARKER: &[u8] = b"Verify return code:";

/// Run `openssl s_client` and return (stdout, stderr) as soon as the handshake summary
/// has been printed, instead of waiting for the process to exit. After a successful
/// TLS 1.3 handshake s_client can linger for seconds waiting on the server to close;
/// we don't need that, so we kill it. On timeout, whatever was captured is returned
/// (the parser decides whether a handshake happened); only an empty capture is a
/// `Timeout` error. The child is always killed and reaped — no orphans.
async fn run_s_client(
    openssl: &str,
    args: &[&str],
    timeout: Duration,
) -> Result<(String, String), ProbeError> {
    use tokio::io::AsyncReadExt;

    let mut child = Command::new(openssl)
        .args(args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()?;

    let mut stdout = child.stdout.take().expect("stdout piped");
    let mut stderr = child.stderr.take().expect("stderr piped");
    let stderr_task = tokio::spawn(async move {
        let mut buf = Vec::new();
        let _ = stderr.read_to_end(&mut buf).await;
        buf
    });

    let mut out = Vec::new();
    let read_until_done = async {
        let mut chunk = [0u8; 8192];
        loop {
            match stdout.read(&mut chunk).await {
                Ok(0) | Err(_) => break, // process exited / pipe closed
                Ok(n) => {
                    out.extend_from_slice(&chunk[..n]);
                    if out
                        .windows(SCLIENT_DONE_MARKER.len())
                        .any(|w| w == SCLIENT_DONE_MARKER)
                    {
                        break;
                    }
                }
            }
        }
    };
    let timed_out = tokio::time::timeout(timeout, read_until_done)
        .await
        .is_err();

    let _ = child.start_kill();
    let _ = child.wait().await;

    let err = tokio::time::timeout(Duration::from_millis(500), stderr_task)
        .await
        .ok()
        .and_then(|r| r.ok())
        .unwrap_or_default();

    if timed_out && out.is_empty() {
        return Err(ProbeError::Timeout);
    }
    Ok((
        String::from_utf8_lossy(&out).into_owned(),
        String::from_utf8_lossy(&err).into_owned(),
    ))
}
