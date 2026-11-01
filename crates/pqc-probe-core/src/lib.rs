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
 
    // Protocol — same label, tolerate 0, 1, 2 or more spaces before the colon.
    let protocol_version = extract_kv(&combined, "Protocol");
 
    // Cipher — 3.0.x has "Cipher    : X", 3.5.x has "New, TLSv1.3, Cipher is X".
    let cipher_raw = extract_kv(&combined, "Cipher")
        .or_else(|| extract_after(&combined, "Cipher is "));
 
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
    let cert_sig_alg =
        extract_chain_sigalg(&combined).or_else(|| extract_cert_sig_alg(&combined));
 
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
            extract_kv(OSSL_30X_SAMPLE, "Server Temp Key").as_deref().and_then(normalize_group),
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
        assert_eq!(normalize_group("X25519, 253 bits"), Some("X25519".to_string()));
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
    fn parses_3_5_x_classical_peer_temp_key(){
        let sample = "Protocol: TLSv1.3\n\
                      New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384\n\
                      Peer Temp Key: X25519, 253 bits\n";
        assert_eq!(
            extract_kv(sample, "Peer Temp Key").as_deref().and_then(normalize_group),
            Some("X25519".to_string())
        );
    }

    #[test]
    fn normalize_group_rejects_null_sentinel(){
        assert_eq!(normalize_group("<NULL>"), None);
    }
}