//! pqc-probe-core — core probe logic for detecting post-quantum algorithms
//! on TLS and SSH endpoints.
//!
//! Week 1 scope: TLS probing by shelling out to `openssl s_client`, vanilla
//! mode only. Experimental mode (with oqs-provider) and SSH probing arrive
//! in Weeks 2 and 3.

use serde::{Deserialize, Serialize};
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
    /// OpenSSL + oqs-provider — the extended codepoint set. Week 2.
    #[allow(dead_code)]
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
    let output = tokio::time::timeout(
        opts.timeout,
        Command::new(&opts.openssl_path)
            .args([
                "s_client",
                "-connect",
                &address,
                "-tls1_3",
                "-groups",
                kem,
                "-servername",
                &target.host,
            ])
            .stdin(std::process::Stdio::null())
            .output(),
    )
    .await
    .map_err(|_| ProbeError::Timeout)??;

    let combined = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let handshake_succeeded = combined.contains("Verify return code") || combined.contains("Session-ID:");

    // Parse interesting lines. OpenSSL's s_client output has stable formats.
    let protocol_version = extract_field(&combined, "Protocol  : ")
        .or_else(|| extract_field(&combined, "Protocol : "));
    let cipher = extract_field(&combined, "Cipher    : ")
        .or_else(|| extract_field(&combined, "Cipher   : "));
    let negotiated = extract_field(&combined, "Server Temp Key: ")
        .or_else(|| extract_field(&combined, "Negotiated group: "));
    let peer_sig_alg = extract_field(&combined, "Peer signature type: ")
        .or_else(|| extract_field(&combined, "Peer signing digest: "));
    let cert_sig_alg = extract_cert_sig_alg(&combined);

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

fn extract_field(text: &str, prefix: &str) -> Option<String> {
    text.lines()
        .find_map(|line| line.trim_start().strip_prefix(prefix).map(|s| s.trim().to_string()))
}

/// Pull the signature algorithm from the "Signature Algorithm:" line that appears
/// twice in openssl's cert dump (TBSCertificate + the outer signature). We take the first.
fn extract_cert_sig_alg(text: &str) -> Option<String> {
    text.lines()
        .find_map(|line| {
            line.trim_start()
                .strip_prefix("Signature Algorithm: ")
                .map(|s| s.trim().to_string())
        })
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

    #[test]
    fn extract_field_works() {
        let text = "    Protocol  : TLSv1.3\n    Cipher    : TLS_AES_256_GCM_SHA384\n";
        assert_eq!(extract_field(text, "Protocol  : "), Some("TLSv1.3".to_string()));
        assert_eq!(
            extract_field(text, "Cipher    : "),
            Some("TLS_AES_256_GCM_SHA384".to_string())
        );
    }
}
