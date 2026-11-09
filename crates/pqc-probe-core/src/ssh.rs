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
use std::collections::{BTreeMap, HashSet};
use std::time::Duration;
use tokio::process::Command;

/// Options for SSH probing.
#[derive(Debug, Clone)]
pub struct SshProbeOptions {
    pub timeout: Duration,
    /// Path to the ssh binary. Defaults to "ssh" from $PATH.
    pub ssh_path: String,
    /// Most `ssh` processes run at once in the per-algorithm phase. Each attempt is a real
    /// connection to the target, so keep this low for hosted use.
    pub max_parallel: usize,
}

impl Default for SshProbeOptions {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(10),
            ssh_path: "ssh".to_string(),
            max_parallel: 4,
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
    /// First line of `ssh -V` for this client, e.g.
    /// "OpenSSH_9.6p1 Ubuntu-3ubuntu13.20, OpenSSL 3.5.2 5 Aug 2025".
    #[serde(default)]
    pub client_version: Option<String>,
}

/// Dual SSH report: mainline ssh client vs OQS-OpenSSH ssh client.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DualSshReport {
    pub target: Target,
    pub vanilla: Option<SshReport>,
    pub experimental: Option<SshReport>,
    pub diff: SshKexDiff,
    /// Why that side's probe failed, if it did (the side's report is then None).
    #[serde(default)]
    pub vanilla_error: Option<String>,
    #[serde(default)]
    pub experimental_error: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SshKexDiff {
    /// KEX algorithms both clients can negotiate.
    pub in_both: Vec<String>,
    /// KEX algorithms only the OQS client can negotiate (the interesting case).
    pub only_experimental: Vec<String>,
    /// KEX algorithms only the vanilla client can negotiate (rare but possible).
    pub only_vanilla: Vec<String>,
    /// For `only_experimental` entries that stock OpenSSH also has in some release:
    /// algorithm -> first mainline version ("9.9"). Entries absent here are truly OQS-only.
    #[serde(default)]
    pub mainline_since: BTreeMap<String, String>,
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
    let client_version = detect_client_version(&opts.ssh_path).await;

    // Phase 2: for each offered KEX, try to negotiate with this client.
    // Run in parallel to keep the whole probe fast.
    let limiter = std::sync::Arc::new(tokio::sync::Semaphore::new(opts.max_parallel.max(1)));
    let mut handles = Vec::with_capacity(server_offered_kex.len());
    for kex in &server_offered_kex {
        let limiter = std::sync::Arc::clone(&limiter);
        let kex = kex.clone();
        let ssh_path = opts.ssh_path.clone();
        let target = target.clone();
        let timeout = opts.timeout;
        handles.push(tokio::spawn(async move {
            let _permit = limiter.acquire_owned().await.ok()?;
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
        client_version,
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

    let (vanilla, vanilla_error) = crate::split_result(vanilla_result);
    let (experimental, experimental_error) = crate::split_result(experimental_result);

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
    let mainline_since = annotate_mainline(&only_experimental);

    Ok(DualSshReport {
        target: target.clone(),
        vanilla,
        experimental,
        vanilla_error,
        experimental_error,
        diff: SshKexDiff {
            in_both,
            only_experimental,
            only_vanilla,
            mainline_since,
        },
    })
}

/// Build the argument list for one `ssh -vv` attempt with a single forced KEX name.
///
/// `-4`: force IPv4. Without it ssh tries the AAAA record first, and on a network with broken
/// IPv6 each attempt stalls for the connect timeout before falling back, which can exceed the
/// probe timeout (same reason every `s_client` call passes `-4`).
/// The host is always the single argument `nobody@<host>`; no shell is involved.
fn ssh_args(host: &str, port: u16, kex: &str) -> Vec<String> {
    vec![
        "-4".to_string(),
        // Ignore ~/.ssh/config and /etc/ssh/ssh_config: a user or system config (ProxyCommand,
        // ProxyJump, Host * options) must not change where or how the probe connects.
        "-F".to_string(),
        "/dev/null".to_string(),
        "-vv".to_string(),
        "-o".to_string(),
        "BatchMode=yes".to_string(),
        "-o".to_string(),
        "StrictHostKeyChecking=no".to_string(),
        "-o".to_string(),
        "UserKnownHostsFile=/dev/null".to_string(),
        "-o".to_string(),
        "PasswordAuthentication=no".to_string(),
        "-o".to_string(),
        "ConnectTimeout=5".to_string(),
        "-o".to_string(),
        format!("KexAlgorithms={}", kex),
        "-p".to_string(),
        port.to_string(),
        format!("nobody@{}", host),
        "exit".to_string(),
    ]
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
    // kill_on_drop: if the timeout below fires, the future is dropped; without this the
    // ssh child would be left running as an orphan.
    let output = tokio::time::timeout(
        timeout,
        Command::new(ssh_path)
            .args(ssh_args(&target.connect_host(), target.port, kex))
            .stdin(std::process::Stdio::null())
            .kill_on_drop(true)
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

/// Parse the OpenSSH (major, minor) out of `ssh -V` output.
///
/// "OpenSSH_9.6p1 Ubuntu-3ubuntu13.20, OpenSSL 3.5.2 ..." -> (9, 6)
/// "OpenSSH_10.4-2026-08_p1, Open Quantum Safe 2026-08, ..." -> (10, 4)
pub fn parse_openssh_version(s: &str) -> Option<(u32, u32)> {
    let rest = s.trim().strip_prefix("OpenSSH_")?;
    let (major, rest) = rest.split_once('.')?;
    let major: u32 = major.parse().ok()?;
    let minor: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
    Some((major, minor.parse().ok()?))
}

/// First stock-OpenSSH release that has this KEX algorithm, for algorithms the OQS fork
/// also offers. Used to tell "needs OQS-OpenSSH" apart from "just needs a newer ssh".
/// Only post-quantum KEX names are listed; anything else returns None.
pub fn mainline_kex_since(alg: &str) -> Option<(u32, u32)> {
    match alg {
        // Vendor-named hybrid sntrup761+X25519: 8.5 per OpenSSH's release notes
        // (recalled from them; not re-checked when this table was written).
        "sntrup761x25519-sha512@openssh.com" => Some((8, 5)),
        // OpenSSH 9.9 notes: the hybrid "now has an IANA-assigned name in addition to the
        // @openssh.com vendor extension name".
        "sntrup761x25519-sha512" => Some((9, 9)),
        // OpenSSH 9.9 notes: "mlkem768x25519-sha256 is available by default".
        "mlkem768x25519-sha256" => Some((9, 9)),
        _ => None,
    }
}

/// For each algorithm that stock OpenSSH has in some release, map it to that version
/// ("9.9"). Algorithms missing from the result are genuinely OQS-only.
pub fn annotate_mainline(algs: &[String]) -> BTreeMap<String, String> {
    algs.iter()
        .filter_map(|a| {
            mainline_kex_since(a).map(|(maj, min)| (a.clone(), format!("{}.{}", maj, min)))
        })
        .collect()
}

/// Run `<ssh> -V` (prints to stderr) and return its first line.
async fn detect_client_version(path: &str) -> Option<String> {
    let out = tokio::time::timeout(
        Duration::from_secs(5),
        Command::new(path)
            .arg("-V")
            .stdin(std::process::Stdio::null())
            .output(),
    )
    .await
    .ok()?
    .ok()?;
    crate::first_nonempty_line(&format!(
        "{}\n{}",
        String::from_utf8_lossy(&out.stderr),
        String::from_utf8_lossy(&out.stdout)
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
            client_version: None,
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
            client_version: None,
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

#[cfg(test)]
mod version_diff_tests {
    use super::*;

    #[test]
    fn parses_openssh_versions() {
        assert_eq!(
            parse_openssh_version("OpenSSH_9.6p1 Ubuntu-3ubuntu13.20, OpenSSL 3.5.2 5 Aug 2025"),
            Some((9, 6))
        );
        assert_eq!(
            parse_openssh_version(
                "OpenSSH_10.4-2026-08_p1, Open Quantum Safe 2026-08, OpenSSL 3.5.2"
            ),
            Some((10, 4))
        );
        assert_eq!(parse_openssh_version("OpenSSH_8.0"), Some((8, 0)));
        assert_eq!(parse_openssh_version("Dropbear v2022.83"), None);
        assert_eq!(parse_openssh_version(""), None);
    }

    #[test]
    fn mainline_table_lookups() {
        assert_eq!(mainline_kex_since("mlkem768x25519-sha256"), Some((9, 9)));
        assert_eq!(mainline_kex_since("sntrup761x25519-sha512"), Some((9, 9)));
        assert_eq!(mainline_kex_since("curve25519-sha256"), None);
        assert_eq!(mainline_kex_since("kyber-512-sha256"), None);
    }

    #[test]
    fn annotate_splits_newer_mainline_from_oqs_only() {
        let only_oqs = vec![
            "mlkem768x25519-sha256".to_string(),
            "sntrup761x25519-sha512".to_string(),
            "some-oqs-only-kex@example.com".to_string(),
        ];
        let m = annotate_mainline(&only_oqs);
        assert_eq!(m.len(), 2);
        assert_eq!(
            m.get("mlkem768x25519-sha256").map(String::as_str),
            Some("9.9")
        );
        assert!(!m.contains_key("some-oqs-only-kex@example.com"));
    }
}

#[cfg(test)]
mod ssh_args_tests {
    use super::*;

    #[test]
    fn forces_ipv4_and_single_kex() {
        let a = ssh_args("github.com", 22, "mlkem768x25519-sha256");
        assert_eq!(a[0], "-4");
        assert!(a.contains(&"KexAlgorithms=mlkem768x25519-sha256".to_string()));
        assert!(a.contains(&"BatchMode=yes".to_string()));
    }

    #[test]
    fn host_is_one_argument_after_the_port() {
        let a = ssh_args("example.com", 2222, "x");
        let n = a.len();
        assert_eq!(a[n - 1], "exit");
        assert_eq!(a[n - 2], "nobody@example.com");
        assert_eq!(a[n - 3], "2222");
        assert_eq!(a[n - 4], "-p");
        // a hostile-looking host stays inside a single `nobody@...` argument
        let h = ssh_args("-oProxyCommand=evil", 22, "x");
        assert_eq!(h[h.len() - 2], "nobody@-oProxyCommand=evil");
        assert_eq!(h.iter().filter(|s| s.contains("ProxyCommand")).count(), 1);
    }
}

#[cfg(test)]
mod ssh_hardening_tests {
    use super::*;

    #[test]
    fn ignores_user_and_system_ssh_config() {
        let a = ssh_args("example.com", 22, "x");
        let i = a.iter().position(|s| s == "-F").expect("-F present");
        assert_eq!(a[i + 1], "/dev/null");
    }

    #[test]
    fn default_parallelism_is_bounded() {
        let o = SshProbeOptions::default();
        assert!(o.max_parallel >= 1 && o.max_parallel <= 8);
    }
}
