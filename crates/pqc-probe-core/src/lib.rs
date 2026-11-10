//! pqc-probe-core — core probe logic for detecting post-quantum algorithms
//! on TLS and SSH endpoints.
//!
//! TLS probing shells out to `openssl s_client` (one handshake per candidate
//! group, run in parallel); dual mode diffs vanilla OpenSSL against
//! OpenSSL + oqs-provider. SSH probing lives in [`ssh`].

pub mod kexinit;
pub mod policy;
pub mod report;
pub mod ssh;

// Re-export at crate root so pqc-probe-cli can `use pqc_probe_core::{SshReport, ...}`.
pub use policy::{check_resolved, prepare_target, Policy, PolicyError};
pub use report::{
    ModeSelection, ProtocolSelection, Report, ReportTarget, RequestInfo, SshClientResult,
    SshSection, TlsSection, SCHEMA_VERSION,
};
pub use ssh::{
    annotate_mainline, mainline_kex_since, parse_openssh_version, probe_ssh, probe_ssh_dual,
    DualSshReport, SshKexDiff, SshProbeOptions, SshReport,
};

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
    /// Pre-resolved, policy-checked address to connect to instead of resolving `host` again
    /// (see [`policy`]). `host` is still used for SNI. Never serialized.
    #[serde(skip)]
    pub resolved: Option<std::net::IpAddr>,
}

impl Target {
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        Self {
            host: host.into(),
            port,
            resolved: None,
        }
    }

    /// Pin this target to an already-checked address.
    pub fn with_resolved(mut self, ip: impl Into<std::net::IpAddr>) -> Self {
        self.resolved = Some(ip.into());
        self
    }

    /// What to connect to: the pinned address if there is one, otherwise the host name.
    pub fn connect_host(&self) -> String {
        match self.resolved {
            Some(ip) => ip.to_string(),
            None => self.host.clone(),
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
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct TlsReport {
    pub protocol_version: Option<String>,
    pub cipher: Option<String>,
    /// Which KEMs the server negotiated when offered. Each entry is "offered → negotiated".
    pub kems_tried: Vec<KemResult>,
    /// Signature algorithm on the server's certificate.
    pub cert_sig_alg: Option<String>,
    /// Signature algorithm used in CertificateVerify (what the server actually signed with).
    pub peer_sig_alg: Option<String>,
    /// Certificate chain as sent by the server (depth 0 = leaf). Empty if none was parsed.
    #[serde(default)]
    pub cert_chain: Vec<CertInfo>,
    /// First line of `<openssl> version` for the client binary used, e.g.
    /// "OpenSSL 3.5.2 5 Aug 2025 (Library: OpenSSL 3.5.2 5 Aug 2025)".
    #[serde(default)]
    pub openssl_version: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
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
    #[error("ssh protocol error: {0}")]
    Protocol(String),
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
    let openssl_version = detect_openssl_version(&opts.openssl_path).await;
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
    let mut cert_chain: Vec<CertInfo> = Vec::new();

    for handle in handles {
        if let Ok(Ok(result)) = handle.await {
            // Capture metadata from the first successful handshake.
            if result.handshake_succeeded {
                protocol_version = protocol_version.or(result.protocol_version);
                cipher = cipher.or(result.cipher);
                cert_sig_alg = cert_sig_alg.or(result.cert_sig_alg);
                peer_sig_alg = peer_sig_alg.or(result.peer_sig_alg);
                if cert_chain.is_empty() {
                    cert_chain = result.cert_chain;
                }
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
        cert_chain,
        openssl_version,
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
    cert_chain: Vec<CertInfo>,
}

async fn try_kem(
    target: &Target,
    opts: &ProbeOptions,
    kem: &str,
) -> Result<KemAttempt, ProbeError> {
    let address = format!("{}:{}", target.connect_host(), target.port);
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
    // OpenSSL 3.5.x prints the "Protocol :" line only in the SSL-Session block, which comes
    // after "Verify return code:" (where we stop reading) -- so fall back to the
    // "New, TLSv1.3, Cipher is ..." summary line, which is always before it.
    let protocol_version =
        extract_kv(&combined, "Protocol").or_else(|| extract_new_line_protocol(&combined));

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

    let negotiated = resolve_negotiated(
        server_temp_raw.as_deref().and_then(normalize_group),
        kem,
        handshake_succeeded,
    );
    let cipher = cipher_raw.filter(|c| !c.contains("(NONE)"));

    // Prefer cert chain's `sigalg:` (clean, 3.5.x emits it on every chain line);
    // fall back to body-of-cert "Signature Algorithm:" line (3.0.x behavior).
    let cert_sig_alg = extract_chain_sigalg(&combined).or_else(|| extract_cert_sig_alg(&combined));

    let cert_chain = parse_cert_chain(&combined);

    Ok(KemAttempt {
        offered: kem.to_string(),
        negotiated,
        handshake_succeeded,
        protocol_version,
        cipher,
        cert_sig_alg,
        peer_sig_alg,
        cert_chain,
    })
}

/// One certificate in the server's chain, as reported by `openssl s_client`.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CertInfo {
    /// 0 = leaf; higher numbers are closer to the root.
    pub depth: u8,
    pub subject: String,
    pub issuer: String,
    pub signature_algorithm: Option<String>,
    /// Key type as openssl prints it, e.g. "id-ecPublicKey", "rsaEncryption", "ML-DSA-65".
    pub public_key_type: Option<String>,
    pub public_key_bits: Option<u32>,
    pub not_before: Option<String>,
    pub not_after: Option<String>,
    /// subject == issuer, i.e. a real root. Servers usually don't send the root, so the
    /// last cert in the chain is typically *not* self-signed.
    pub self_signed: bool,
    /// The signature algorithm or the key type is post-quantum.
    pub post_quantum: bool,
}

/// True if an algorithm / key-type name is a post-quantum signature scheme.
/// True for TLS group names that contain a post-quantum KEM (ML-KEM, Kyber, Frodo, ...).
pub fn is_pq_group_name(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    ["mlkem", "kyber", "frodo", "bike", "hqc", "sntrup"]
        .iter()
        .any(|p| n.contains(p))
}

/// True if this client completed a handshake using at least one post-quantum group, i.e. the
/// "vanilla" stack is already PQ-capable and a vanilla-vs-experimental TLS diff says little.
pub fn has_pq_group(r: &TlsReport) -> bool {
    r.kems_tried
        .iter()
        .any(|k| k.handshake_succeeded && is_pq_group_name(&k.offered))
}

pub fn is_pq_signature_name(name: &str) -> bool {
    let n = name.to_ascii_uppercase();
    [
        "ML-DSA",
        "MLDSA",
        "SLH-DSA",
        "SLHDSA",
        "DILITHIUM",
        "FALCON",
        "FN-DSA",
        "SPHINCS",
    ]
    .iter()
    .any(|p| n.contains(p))
}

/// Parse the "Certificate chain" block of `openssl s_client` output.
///
/// Handles the 3.x format:
/// ```text
/// Certificate chain
///  0 s:CN = github.com
///    i:C = GB, O = Sectigo Limited, CN = ...
///    a:PKEY: id-ecPublicKey, 256 (bit); sigalg: ecdsa-with-SHA256
///    v:NotBefore: Oct 30 00:00:00 2026 GMT; NotAfter: Jan 27 23:59:59 2027 GMT
/// ```
/// Every field except depth and subject is optional; PEM bodies (from `-showcerts`)
/// are ignored. Returns an empty Vec when there is no chain block.
pub fn parse_cert_chain(text: &str) -> Vec<CertInfo> {
    let mut chain: Vec<CertInfo> = Vec::new();
    let mut in_chain = false;

    for line in text.lines() {
        let t = line.trim();
        if !in_chain {
            if t == "Certificate chain" {
                in_chain = true;
            }
            continue;
        }
        if t == "---" {
            break; // end of block (PEM armor lines have 5 dashes, so they don't match)
        }

        // Entry header: "<depth> s:<subject>"
        if let Some((num, rest)) = t.split_once(' ') {
            if let (Ok(depth), Some(subject)) = (num.parse::<u8>(), rest.strip_prefix("s:")) {
                chain.push(CertInfo {
                    depth,
                    subject: subject.trim().to_string(),
                    issuer: String::new(),
                    signature_algorithm: None,
                    public_key_type: None,
                    public_key_bits: None,
                    not_before: None,
                    not_after: None,
                    self_signed: false,
                    post_quantum: false,
                });
                continue;
            }
        }

        if let Some(c) = chain.last_mut() {
            if let Some(v) = t.strip_prefix("i:") {
                c.issuer = v.trim().to_string();
            } else if let Some(v) = t.strip_prefix("a:") {
                parse_chain_a_line(c, v);
            } else if let Some(v) = t.strip_prefix("v:") {
                parse_chain_v_line(c, v);
            }
        }
    }

    for c in &mut chain {
        c.self_signed = !c.subject.is_empty() && c.subject == c.issuer;
        c.post_quantum = c
            .signature_algorithm
            .as_deref()
            .map(is_pq_signature_name)
            .unwrap_or(false)
            || c.public_key_type
                .as_deref()
                .map(is_pq_signature_name)
                .unwrap_or(false);
    }
    chain
}

/// "PKEY: id-ecPublicKey, 256 (bit); sigalg: ecdsa-with-SHA256"
/// "PKEY: ML-DSA-65; sigalg: ML-DSA-65"   (no comma, no bit count)
fn parse_chain_a_line(c: &mut CertInfo, s: &str) {
    for part in s.split(';') {
        let part = part.trim();
        if let Some(rest) = part.strip_prefix("PKEY:") {
            let rest = rest.trim();
            let (ty, tail) = match rest.split_once(',') {
                Some((a, b)) => (a.trim(), b.trim()),
                None => (rest, ""),
            };
            if !ty.is_empty() {
                c.public_key_type = Some(ty.to_string());
            }
            // tail is "256 (bit)" on 3.x; older builds print a curve name instead.
            c.public_key_bits = tail
                .split_whitespace()
                .next()
                .and_then(|n| n.parse::<u32>().ok());
        } else if let Some(rest) = part.strip_prefix("sigalg:") {
            let rest = rest.trim();
            if !rest.is_empty() {
                c.signature_algorithm = Some(rest.to_string());
            }
        }
    }
}

/// "NotBefore: Oct 30 00:00:00 2026 GMT; NotAfter: Jan 27 23:59:59 2027 GMT"
fn parse_chain_v_line(c: &mut CertInfo, s: &str) {
    for part in s.split(';') {
        let part = part.trim();
        if let Some(rest) = part.strip_prefix("NotBefore:") {
            c.not_before = Some(rest.trim().to_string());
        } else if let Some(rest) = part.strip_prefix("NotAfter:") {
            c.not_after = Some(rest.trim().to_string());
        }
    }
}

/// First non-empty line of `text`, trimmed.
pub(crate) fn first_nonempty_line(text: &str) -> Option<String> {
    text.lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .map(String::from)
}

/// Run `<openssl> version` and return its first line (None if it can't be run).
async fn detect_openssl_version(path: &str) -> Option<String> {
    let out = tokio::time::timeout(
        Duration::from_secs(5),
        Command::new(path)
            .arg("version")
            .stdin(std::process::Stdio::null())
            .output(),
    )
    .await
    .ok()?
    .ok()?;
    first_nonempty_line(&String::from_utf8_lossy(&out.stdout))
}

/// Decide the negotiated group for one single-group attempt.
///
/// We offer exactly one group per attempt (`-groups <kem>`), so a successful handshake can
/// only have used that group. Some openssl builds don't report it -- notably a 3.0.x
/// `s_client` binary linked against the 3.5.x library can't print a hybrid group's name --
/// so when nothing was reported but the handshake worked, fall back to the offered group.
/// A reported value always wins; a failed handshake never yields a group.
fn resolve_negotiated(
    reported: Option<String>,
    offered: &str,
    handshake_ok: bool,
) -> Option<String> {
    match reported {
        Some(g) => Some(g),
        None if handshake_ok => Some(offered.to_string()),
        None => None,
    }
}

/// Protocol from the handshake summary line "New, TLSv1.3, Cipher is TLS_AES_128_GCM_SHA256".
/// A failed handshake prints "New, (NONE), Cipher is (NONE)"; that yields None.
fn extract_new_line_protocol(text: &str) -> Option<String> {
    text.lines().find_map(|line| {
        let rest = line.trim().strip_prefix("New, ")?;
        let (proto, _) = rest.split_once(", Cipher is")?;
        let proto = proto.trim();
        if proto.is_empty() || proto.contains("NONE") {
            None
        } else {
            Some(proto.to_string())
        }
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
    /// Why that side's probe failed, if it did (the side's report is then None).
    #[serde(default)]
    pub vanilla_error: Option<String>,
    #[serde(default)]
    pub experimental_error: Option<String>,
}

/// Diff summary across the two probes' negotiated KEM sets.
#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
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

    let (vanilla, vanilla_error) = split_result(vanilla_result);
    let (experimental, experimental_error) = split_result(experimental_result);

    let diff = compute_diff(vanilla.as_ref(), experimental.as_ref());

    Ok(DualProbeReport {
        target: target.clone(),
        vanilla,
        experimental,
        diff,
        vanilla_error,
        experimental_error,
    })
}

/// Keep a probe's error text instead of discarding it, so reports can say why a side is empty.
pub(crate) fn split_result<T>(r: Result<T, ProbeError>) -> (Option<T>, Option<String>) {
    match r {
        Ok(v) => (Some(v), None),
        Err(e) => (None, Some(e.to_string())),
    }
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
                cert_chain: vec![],
                openssl_version: None,
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
/// Every field the parser needs (chain, peer sig, group, cipher, protocol) comes before it,
/// except the "Protocol :" line on 3.5.x, which is recovered from the "New, ..." line.
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

#[cfg(test)]
mod chain_tests {
    use super::*;

    /// Trimmed from a real `openssl s_client -showcerts -connect github.com:443` capture
    /// (OpenSSL 3.5.2 library), PEM bodies shortened.
    const GITHUB_CAPTURE: &str = r#"depth=2 C = GB, O = Sectigo Limited, CN = Sectigo Public Server Authentication Root E46
verify error:num=20:unable to get local issuer certificate
CONNECTED(00000003)
---
Certificate chain
 0 s:CN = github.com
   i:C = GB, O = Sectigo Limited, CN = Sectigo Public Server Authentication CA DV E36
   a:PKEY: id-ecPublicKey, 256 (bit); sigalg: ecdsa-with-SHA256
   v:NotBefore: Oct 30 00:00:00 2026 GMT; NotAfter: Jan 27 23:59:59 2027 GMT
-----BEGIN CERTIFICATE-----
MIIFAKEFAKEFAKE
-----END CERTIFICATE-----
 1 s:C = GB, O = Sectigo Limited, CN = Sectigo Public Server Authentication CA DV E36
   i:C = GB, O = Sectigo Limited, CN = Sectigo Public Server Authentication Root E46
   a:PKEY: id-ecPublicKey, 256 (bit); sigalg: ecdsa-with-SHA384
   v:NotBefore: Mar 22 00:00:00 2021 GMT; NotAfter: Mar 21 23:59:59 2036 GMT
-----BEGIN CERTIFICATE-----
MIIFAKEFAKEFAKE
-----END CERTIFICATE-----
 2 s:C = GB, O = Sectigo Limited, CN = Sectigo Public Server Authentication Root E46
   i:C = US, ST = New Jersey, L = Jersey City, O = The USERTRUST Network, CN = USERTrust ECC Certification Authority
   a:PKEY: id-ecPublicKey, 384 (bit); sigalg: ecdsa-with-SHA384
   v:NotBefore: Mar 22 00:00:00 2021 GMT; NotAfter: Jan 18 23:59:59 2038 GMT
-----BEGIN CERTIFICATE-----
MIIFAKEFAKEFAKE
-----END CERTIFICATE-----
---
Server certificate
subject=CN = github.com
"#;

    #[test]
    fn parses_github_chain() {
        let chain = parse_cert_chain(GITHUB_CAPTURE);
        assert_eq!(chain.len(), 3);
        assert_eq!(
            chain.iter().map(|c| c.depth).collect::<Vec<_>>(),
            vec![0, 1, 2]
        );
        assert_eq!(chain[0].subject, "CN = github.com");
        assert_eq!(
            chain[0].signature_algorithm.as_deref(),
            Some("ecdsa-with-SHA256")
        );
        assert_eq!(chain[0].public_key_type.as_deref(), Some("id-ecPublicKey"));
        assert_eq!(chain[0].public_key_bits, Some(256));
        assert_eq!(chain[2].public_key_bits, Some(384));
        assert_eq!(
            chain[0].not_before.as_deref(),
            Some("Oct 30 00:00:00 2026 GMT")
        );
        assert_eq!(
            chain[0].not_after.as_deref(),
            Some("Jan 27 23:59:59 2027 GMT")
        );
        // each cert's issuer is the next cert's subject
        assert_eq!(chain[0].issuer, chain[1].subject);
        assert_eq!(chain[1].issuer, chain[2].subject);
    }

    #[test]
    fn github_chain_is_classical_and_root_not_sent() {
        let chain = parse_cert_chain(GITHUB_CAPTURE);
        assert!(chain.iter().all(|c| !c.post_quantum));
        // The server stops at an intermediate; the real root (USERTrust) isn't sent.
        assert!(chain.iter().all(|c| !c.self_signed));
    }

    #[test]
    fn detects_self_signed_root() {
        let text = "Certificate chain\n 0 s:CN = Root\n   i:CN = Root\n---\n";
        let chain = parse_cert_chain(text);
        assert_eq!(chain.len(), 1);
        assert!(chain[0].self_signed);
        assert_eq!(chain[0].signature_algorithm, None);
    }

    #[test]
    fn flags_pq_certs_without_bit_count() {
        let text = "Certificate chain\n\
 0 s:CN = pq.example\n\
   i:CN = Classical CA\n\
   a:PKEY: ML-DSA-65; sigalg: ML-DSA-65\n\
 1 s:CN = Classical CA\n\
   i:CN = Classical Root\n\
   a:PKEY: rsaEncryption, 2048 (bit); sigalg: sha256WithRSAEncryption\n\
---\n";
        let chain = parse_cert_chain(text);
        assert_eq!(chain.len(), 2);
        assert!(chain[0].post_quantum);
        assert_eq!(chain[0].public_key_type.as_deref(), Some("ML-DSA-65"));
        assert_eq!(chain[0].public_key_bits, None);
        assert!(!chain[1].post_quantum);
        assert_eq!(chain[1].public_key_bits, Some(2048));
    }

    #[test]
    fn pq_name_detection() {
        assert!(is_pq_signature_name("ML-DSA-44"));
        assert!(is_pq_signature_name("SLH-DSA-SHA2-128s"));
        assert!(is_pq_signature_name("p256_mldsa44"));
        assert!(!is_pq_signature_name("ecdsa-with-SHA256"));
        assert!(!is_pq_signature_name("sha256WithRSAEncryption"));
    }

    #[test]
    fn no_chain_block_gives_empty() {
        assert!(parse_cert_chain("CONNECTED(00000003)\nsome other output\n").is_empty());
        assert!(parse_cert_chain("").is_empty());
    }
}

#[cfg(test)]
mod protocol_tests {
    use super::*;

    /// Lines from a real 3.5.2-library `s_client -tls1_3 -groups X25519` run against github.com
    /// (no "Protocol :" line before "Verify return code:").
    const GITHUB_SUMMARY: &str = "\
Server Temp Key: X25519, 253 bits\n\
SSL handshake has read 3095 bytes and written 1614 bytes\n\
New, TLSv1.3, Cipher is TLS_AES_128_GCM_SHA256\n\
Server public key is 256 bit\n\
Verify return code: 20 (unable to get local issuer certificate)\n";

    #[test]
    fn protocol_from_new_line() {
        assert_eq!(
            extract_new_line_protocol(GITHUB_SUMMARY).as_deref(),
            Some("TLSv1.3")
        );
        // and there is genuinely no "Protocol :" line to find
        assert_eq!(extract_kv(GITHUB_SUMMARY, "Protocol"), None);
    }

    #[test]
    fn failed_handshake_has_no_protocol() {
        let text = "New, (NONE), Cipher is (NONE)\n";
        assert_eq!(extract_new_line_protocol(text), None);
        assert_eq!(extract_new_line_protocol("nothing here"), None);
    }
}

#[cfg(test)]
mod negotiated_tests {
    use super::*;

    #[test]
    fn reported_group_wins() {
        assert_eq!(
            resolve_negotiated(Some("X25519".into()), "X25519MLKEM768", true).as_deref(),
            Some("X25519")
        );
    }

    #[test]
    fn unreported_group_falls_back_to_offered_on_success() {
        assert_eq!(
            resolve_negotiated(None, "X25519MLKEM768", true).as_deref(),
            Some("X25519MLKEM768")
        );
    }

    #[test]
    fn failed_handshake_never_yields_a_group() {
        assert_eq!(resolve_negotiated(None, "P-384", false), None);
    }
}

#[cfg(test)]
mod version_tests {
    use super::*;

    #[test]
    fn first_nonempty_line_skips_blanks_and_trims() {
        assert_eq!(
            first_nonempty_line("\n  \nOpenSSL 3.5.2 5 Aug 2025  \nsecond\n").as_deref(),
            Some("OpenSSL 3.5.2 5 Aug 2025")
        );
        assert_eq!(first_nonempty_line("  \n"), None);
    }
}

#[cfg(test)]
mod target_tests {
    use super::*;

    fn kem(name: &str, ok: bool) -> KemResult {
        KemResult {
            offered: name.to_string(),
            negotiated: ok.then(|| name.to_string()),
            handshake_succeeded: ok,
        }
    }

    #[test]
    fn pq_group_names() {
        assert!(is_pq_group_name("X25519MLKEM768"));
        assert!(is_pq_group_name("SecP384r1MLKEM1024"));
        assert!(is_pq_group_name("x25519_kyber768"));
        assert!(!is_pq_group_name("X25519"));
        assert!(!is_pq_group_name("P-384"));
    }

    fn tls_report(kems: Vec<KemResult>) -> TlsReport {
        TlsReport {
            protocol_version: None,
            cipher: None,
            kems_tried: kems,
            cert_sig_alg: None,
            peer_sig_alg: None,
            cert_chain: Vec::new(),
            openssl_version: None,
        }
    }

    #[test]
    fn has_pq_group_needs_a_successful_pq_handshake() {
        let r = tls_report(vec![kem("X25519", true), kem("X25519MLKEM768", false)]);
        assert!(!has_pq_group(&r));
        let r = tls_report(vec![kem("X25519", true), kem("X25519MLKEM768", true)]);
        assert!(has_pq_group(&r));
    }

    #[test]
    fn connect_host_prefers_resolved_address() {
        let t = Target::new("example.com", 443);
        assert_eq!(t.connect_host(), "example.com");
        let t = t.with_resolved(std::net::Ipv4Addr::new(93, 184, 216, 34));
        assert_eq!(t.connect_host(), "93.184.216.34");
        assert_eq!(t.host, "example.com"); // still the SNI name
    }

    #[test]
    fn resolved_address_is_not_serialized() {
        let t = Target::new("example.com", 443).with_resolved(std::net::Ipv4Addr::new(1, 2, 3, 4));
        assert_eq!(
            serde_json::to_string(&t).unwrap(),
            r#"{"host":"example.com","port":443}"#
        );
        let back: Target = serde_json::from_str(r#"{"host":"example.com","port":443}"#).unwrap();
        assert!(back.resolved.is_none());
    }
}
