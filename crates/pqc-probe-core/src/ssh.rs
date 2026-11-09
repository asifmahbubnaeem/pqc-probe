//! SSH probing: shells out to `ssh -vv` and parses the KEX negotiation.
//!
//! Technique: probe the server's offer list in ONE connection by requesting a
//! KEX name the server can't match. OpenSSH prints "Their offer: X,Y,Z" when
//! it can't find a mutually-supported algorithm. That gives us the full server
//! offer in ~2 seconds, no per-algorithm probing needed.
//!
//! For dual-mode (mainline vs OQS-OpenSSH client), we run the probe twice —
//! once with each client — and compare which algorithms each client can
//! actually negotiate from the server's offer.

use crate::{ProbeError, Target};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::time::Duration;
use tokio::process::Command;

/// Options for SSH probing.
#[derive(Debug, Clone)]
pub struct SshProbeOptions {
    pub timeout: Duration,
    /// Path to the ssh binary. Defaults to "ssh" from $PATH.
    pub ssh_path: String,
}

impl Default for SshProbeOptions {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(10),
            ssh_path: "ssh".to_string(),
        }
    }
}

/// SSH probe report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshReport {
    pub target: Target,
    pub server_version: Option<String>,
    /// Full KEX algorithm list the server offered.
    pub server_offered_kex: Vec<String>,
    /// Of the server's offer, which ones this client can actually negotiate.
    pub client_can_negotiate: Vec<String>,
}

/// Dual SSH report: mainline ssh client vs OQS-OpenSSH ssh client.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DualSshReport {
    pub target: Target,
    pub vanilla: Option<SshReport>,
    pub experimental: Option<SshReport>,
    pub diff: SshKexDiff,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SshKexDiff {
    /// KEX algorithms both clients can negotiate.
    pub in_both: Vec<String>,
    /// KEX algorithms only the OQS client can negotiate (the interesting case).
    pub only_experimental: Vec<String>,
    /// KEX algorithms only the vanilla client can negotiate (rare but possible).
    pub only_vanilla: Vec<String>,
}

/// Probe an SSH target.
///
/// Two-phase:
///   1. One ssh call with a nonexistent KEX name → parse "Their offer:" for the full server offer.
///   2. For each entry in the offer, try to negotiate it with this client → see which succeed.
pub async fn probe_ssh(target: &Target, opts: &SshProbeOptions) -> Result<SshReport, ProbeError> {
    // Phase 1: enumerate server's offer.
    let enum_output = run_ssh(
        &opts.ssh_path,
        target,
        opts.timeout,
        "diffie-hellman-group1-sha1",
    )
    .await?;

    let server_offered_kex = parse_server_offer(&enum_output);
    let server_version = parse_server_version(&enum_output);

    // Phase 2: for each offered KEX, try to negotiate with this client.
    // Run in parallel to keep the whole probe fast.
    let mut handles = Vec::with_capacity(server_offered_kex.len());
    for kex in &server_offered_kex {
        let kex = kex.clone();
        let ssh_path = opts.ssh_path.clone();
        let target = target.clone();
        let timeout = opts.timeout;
        handles.push(tokio::spawn(async move {
            let output = run_ssh(&ssh_path, &target, timeout, &kex).await.ok()?;
            if negotiated_kex(&output).as_deref() == Some(kex.as_str()) {
                Some(kex)
            } else {
                None
            }
        }));
    }

    let mut client_can_negotiate = Vec::new();
    for h in handles {
        if let Ok(Some(kex)) = h.await {
            client_can_negotiate.push(kex);
        }
    }
    client_can_negotiate.sort();

    Ok(SshReport {
        target: target.clone(),
        server_version,
        server_offered_kex,
        client_can_negotiate,
    })
}

/// Run both clients against the same target and diff.
pub async fn probe_ssh_dual(
    target: &Target,
    vanilla_opts: &SshProbeOptions,
    experimental_opts: &SshProbeOptions,
) -> Result<DualSshReport, ProbeError> {
    let (vanilla_result, experimental_result) = tokio::join!(
        probe_ssh(target, vanilla_opts),
        probe_ssh(target, experimental_opts),
    );

    let vanilla = vanilla_result.ok();
    let experimental = experimental_result.ok();

    let v_set: HashSet<String> = vanilla
        .as_ref()
        .map(|r| r.client_can_negotiate.iter().cloned().collect())
        .unwrap_or_default();
    let e_set: HashSet<String> = experimental
        .as_ref()
        .map(|r| r.client_can_negotiate.iter().cloned().collect())
        .unwrap_or_default();

    let mut only_experimental: Vec<String> = e_set.difference(&v_set).cloned().collect();
    let mut only_vanilla: Vec<String> = v_set.difference(&e_set).cloned().collect();
    let mut in_both: Vec<String> = e_set.intersection(&v_set).cloned().collect();
    only_experimental.sort();
    only_vanilla.sort();
    in_both.sort();

    Ok(DualSshReport {
        target: target.clone(),
        vanilla,
        experimental,
        diff: SshKexDiff {
            in_both,
            only_experimental,
            only_vanilla,
        },
    })
}

async fn run_ssh(
    ssh_path: &str,
    target: &Target,
    timeout: Duration,
    kex: &str,
) -> Result<String, ProbeError> {
    // -vv for debug output we parse; disable auth prompts; fail fast on first
    // connect timeout. ssh will exit non-zero whether KEX fails or auth fails;
    // we parse stderr either way.
    let host_arg = format!("nobody@{}", target.host);
    let kex_arg = format!("KexAlgorithms={}", kex);
    let port_arg = target.port.to_string();

    let output = tokio::time::timeout(
        timeout,
        Command::new(ssh_path)
            .args([
                "-vv",
                "-o",
                "BatchMode=yes",
                "-o",
                "StrictHostKeyChecking=no",
                "-o",
                "UserKnownHostsFile=/dev/null",
                "-o",
                "PasswordAuthentication=no",
                "-o",
                "ConnectTimeout=5",
                "-o",
                &kex_arg,
                "-p",
                &port_arg,
                &host_arg,
                "exit",
            ])
            .stdin(std::process::Stdio::null())
            .output(),
    )
    .await
    .map_err(|_| ProbeError::Timeout)??;

    Ok(format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    ))
}

/// Parse the server's offered KEX list from "Their offer: X,Y,Z" line.
fn parse_server_offer(text: &str) -> Vec<String> {
    text.lines()
        .find_map(|line| {
            line.split_once("Their offer: ")
                .map(|(_, after)| after.trim())
        })
        .map(|offer| {
            offer
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

/// Parse "debug1: Remote protocol version 2.0, remote software version <X>" for X.
fn parse_server_version(text: &str) -> Option<String> {
    text.lines().find_map(|line| {
        line.split_once("remote software version ")
            .map(|(_, after)| after.trim().to_string())
            .filter(|s| !s.is_empty())
    })
}

/// Parse "debug1: kex: algorithm: X" for X.
fn negotiated_kex(text: &str) -> Option<String> {
    text.lines().find_map(|line| {
        line.split_once("kex: algorithm: ")
            .map(|(_, after)| after.trim().to_string())
            .filter(|s| !s.is_empty())
    })
}

#[cfg(test)]
mod ssh_tests {
    use super::*;

    const OFFER_SAMPLE: &str = "\
debug1: Local version string SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.19\n\
debug1: Remote protocol version 2.0, remote software version OpenSSH_9.6p1 Ubuntu-3ubuntu13.9\n\
Unable to negotiate with 1.2.3.4 port 22: no matching key exchange method found. Their offer: curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,sntrup761x25519-sha512@openssh.com,mlkem768x25519-sha256,diffie-hellman-group14-sha256\n\
";

    const NEGOTIATED_SAMPLE: &str = "\
debug1: Local version string SSH-2.0-OpenSSH_9.6p1\n\
debug1: Remote protocol version 2.0, remote software version OpenSSH_9.6p1\n\
debug1: kex: algorithm: curve25519-sha256\n\
debug1: kex: host key algorithm: ssh-ed25519\n\
";

    #[test]
    fn parses_server_offer() {
        let offer = parse_server_offer(OFFER_SAMPLE);
        assert_eq!(offer.len(), 8);
        assert!(offer.contains(&"curve25519-sha256".to_string()));
        assert!(offer.contains(&"sntrup761x25519-sha512@openssh.com".to_string()));
        assert!(offer.contains(&"mlkem768x25519-sha256".to_string()));
    }

    #[test]
    fn parses_server_version() {
        assert_eq!(
            parse_server_version(OFFER_SAMPLE),
            Some("OpenSSH_9.6p1 Ubuntu-3ubuntu13.9".to_string())
        );
    }

    #[test]
    fn parses_negotiated_kex() {
        assert_eq!(
            negotiated_kex(NEGOTIATED_SAMPLE),
            Some("curve25519-sha256".to_string())
        );
    }

    #[test]
    fn offer_absent_returns_empty() {
        let empty = "debug1: Connecting to 1.2.3.4\n";
        assert_eq!(parse_server_offer(empty), Vec::<String>::new());
    }

    #[test]
    fn diff_captures_oqs_additions() {
        let v = SshReport {
            target: Target::new("example.com", 22),
            server_version: None,
            server_offered_kex: vec![],
            client_can_negotiate: vec!["curve25519-sha256".into(), "mlkem768x25519-sha256".into()],
        };
        let e = SshReport {
            target: Target::new("example.com", 22),
            server_version: None,
            server_offered_kex: vec![],
            client_can_negotiate: vec![
                "curve25519-sha256".into(),
                "mlkem768x25519-sha256".into(),
                "sntrup761x25519-sha512@openssh.com".into(),
            ],
        };

        let v_set: HashSet<String> = v.client_can_negotiate.into_iter().collect();
        let e_set: HashSet<String> = e.client_can_negotiate.into_iter().collect();
        let only_e: Vec<String> = e_set.difference(&v_set).cloned().collect();
        assert_eq!(
            only_e,
            vec!["sntrup761x25519-sha512@openssh.com".to_string()]
        );
    }
}
