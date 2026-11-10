//! SSH probing: shells out to `ssh -vv` and parses the KEX negotiation.
//!
//! Technique: read the server's KEXINIT packet directly (see `kexinit`) for its full offer,
//! then try each offered algorithm with the real ssh client. The old method (a KEX name the
//! server can't match, parsing OpenSSH's "Their offer: X,Y,Z") remains only as a fallback,
//! because OpenSSH truncates that log line at about 1 KB.
//!
//! For dual-mode (mainline vs OQS-OpenSSH client), we run the probe twice —
//! once with each client — and compare which algorithms each client can
//! actually negotiate from the server's offer.

use crate::{ProbeError, Target};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncRead, BufReader};
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
    /// How many post-quantum algorithms get a real handshake test after the traffic-free
    /// `ssh -Q kex` check. Each test is a connection to the target, and sshd 9.8+ penalizes
    /// sources that connect and drop, so keep this small. 0 = no handshake tests.
    pub max_verify: usize,
    /// Pause after each handshake test, while the test slot is still held. OpenSSH 9.8+ servers
    /// (`PerSourcePenalties`, on by default) charge a source about 1 s for every connection that
    /// ends before authentication and refuse the source once the total passes a threshold
    /// (observed: "activating ipv4 penalty of 16 seconds"). About one connection per second
    /// per client keeps the total near zero.
    pub pace: Duration,
}

impl Default for SshProbeOptions {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(10),
            ssh_path: "ssh".to_string(),
            max_parallel: 1,
            max_verify: 8,
            pace: Duration::from_millis(1100),
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
    /// Offered algorithms this client could not be tested on (timeouts, dropped connections),
    /// even after a retry. Neither "supported" nor "unsupported": left out of the diff.
    #[serde(default)]
    pub client_inconclusive: Vec<String>,
    /// Subset of `client_can_negotiate` that completed a real key exchange with the target.
    /// The rest are algorithms the client implements (`ssh -Q kex`) but were not tested.
    #[serde(default)]
    pub client_verified: Vec<String>,
    /// Offered algorithms the client implements but whose key exchange definitely failed
    /// (for example Classic McEliece keys too large for the client).
    #[serde(default)]
    pub client_failed: Vec<String>,
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

#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
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
    // Phase 1: enumerate the server's offer by reading its KEXINIT off the wire (complete list,
    // no dependence on this client's debug output). If that fails, fall back to scraping
    // "Their offer:" from ssh -- which OpenSSH truncates at about 1 KB.
    let (server_offered_kex, server_version) =
        match crate::kexinit::read_server_kexinit(target, opts.timeout).await {
            Ok(k) => (k.kex_algorithms, k.software_version),
            Err(native_err) => {
                let out = run_ssh(
                    &opts.ssh_path,
                    target,
                    opts.timeout,
                    "diffie-hellman-group1-sha1",
                )
                .await?;
                let offer = parse_server_offer(&out);
                if offer.is_empty() {
                    return Err(ProbeError::Protocol(format!(
                        "could not read the server's key-exchange offer \
                         (direct read: {native_err}; ssh said: {})",
                        diagnostic_line(&out)
                    )));
                }
                (offer, parse_server_version(&out))
            }
        };
    let client_version = detect_client_version(&opts.ssh_path).await;

    // Phase 2a (no network traffic): which offered algorithms does this client implement?
    // `ssh -Q kex` lists them. If that fails, fall back to testing every offered algorithm.
    let candidates: Vec<String> = server_offered_kex
        .iter()
        .filter(|k| !is_protocol_marker(k))
        .cloned()
        .collect();
    let (mut usable, to_verify): (BTreeSet<String>, Vec<String>) =
        match query_client_kex(&opts.ssh_path, opts.timeout).await {
            Some(supported) => {
                let usable: BTreeSet<String> = candidates
                    .iter()
                    .filter(|k| supported.contains(*k))
                    .cloned()
                    .collect();
                let to_verify = pick_to_verify(&candidates, &usable, opts.max_verify);
                (usable, to_verify)
            }
            None => (BTreeSet::new(), candidates.clone()),
        };

    // Phase 2b: a real handshake for a few post-quantum algorithms (or all, in the fallback).
    let limiter = std::sync::Arc::new(tokio::sync::Semaphore::new(opts.max_parallel.max(1)));
    let mut handles = Vec::with_capacity(to_verify.len());
    for kex in to_verify {
        let limiter = std::sync::Arc::clone(&limiter);
        let ssh_path = opts.ssh_path.clone();
        let target = target.clone();
        let timeout = opts.timeout;
        let pace = opts.pace;
        handles.push(tokio::spawn(async move {
            let _permit = limiter.acquire_owned().await.ok()?;
            let outcome = try_kex(&ssh_path, &target, timeout, &kex).await;
            // Keep the slot while pausing, so the next test starts no sooner than `pace` later.
            tokio::time::sleep(pace).await;
            Some((kex, outcome))
        }));
    }

    let mut client_verified = Vec::new();
    let mut client_failed = Vec::new();
    let mut client_inconclusive = Vec::new();
    for h in handles {
        if let Ok(Some((kex, outcome))) = h.await {
            match outcome {
                KexOutcome::Negotiated => {
                    usable.insert(kex.clone());
                    client_verified.push(kex);
                }
                KexOutcome::NotNegotiable => {
                    usable.remove(&kex);
                    client_failed.push(kex);
                }
                KexOutcome::Inconclusive => {
                    usable.remove(&kex);
                    client_inconclusive.push(kex);
                }
            }
        }
    }
    let client_can_negotiate: Vec<String> = usable.into_iter().collect();
    client_verified.sort();
    client_failed.sort();
    client_inconclusive.sort();

    Ok(SshReport {
        target: target.clone(),
        server_version,
        server_offered_kex,
        client_can_negotiate,
        client_inconclusive,
        client_verified,
        client_failed,
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

    // An algorithm one side could not be tested on is left out of the diff, not guessed.
    let v_inc = inconclusive_set(vanilla.as_ref());
    let e_inc = inconclusive_set(experimental.as_ref());
    let mut only_experimental: Vec<String> = e_set
        .difference(&v_set)
        .filter(|k| !v_inc.contains(*k))
        .cloned()
        .collect();
    let mut only_vanilla: Vec<String> = v_set
        .difference(&e_set)
        .filter(|k| !e_inc.contains(*k))
        .cloned()
        .collect();
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

/// The algorithms this ssh client implements, from `ssh -Q kex` (no network traffic).
/// None if the command fails or lists nothing.
async fn query_client_kex(ssh_path: &str, timeout: Duration) -> Option<HashSet<String>> {
    let out = tokio::time::timeout(
        timeout,
        Command::new(ssh_path)
            .args(["-Q", "kex"])
            .stdin(std::process::Stdio::null())
            .kill_on_drop(true)
            .output(),
    )
    .await
    .ok()?
    .ok()?;
    if !out.status.success() {
        return None;
    }
    let set = parse_query_list(&String::from_utf8_lossy(&out.stdout));
    (!set.is_empty()).then_some(set)
}

/// One name per line, as printed by `ssh -Q`.
fn parse_query_list(text: &str) -> HashSet<String> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(str::to_string)
        .collect()
}

/// Post-quantum or hybrid KEX names (ML-KEM, sntrup, Kyber, Frodo, BIKE, McEliece, HQC).
fn is_pq_kex_name(name: &str) -> bool {
    crate::is_pq_group_name(name) || name.to_ascii_lowercase().contains("mceliece")
}

/// Lower sorts first: standardized ML-KEM, then OpenSSH's sntrup, then everything else.
fn verify_priority(name: &str) -> u8 {
    let n = name.to_ascii_lowercase();
    if n.contains("mlkem") {
        0
    } else if n.contains("sntrup") {
        1
    } else {
        2
    }
}

/// Which usable algorithms get a real handshake: post-quantum ones only, most important
/// first (ties keep the server's order), at most `max`.
fn pick_to_verify(offered: &[String], usable: &BTreeSet<String>, max: usize) -> Vec<String> {
    let mut pq: Vec<String> = offered
        .iter()
        .filter(|k| usable.contains(*k) && is_pq_kex_name(k))
        .cloned()
        .collect();
    pq.sort_by_key(|k| verify_priority(k)); // stable
    pq.truncate(max);
    pq
}

/// Result of trying one KEX algorithm with one ssh client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KexOutcome {
    /// The key exchange completed (`SSH2_MSG_NEWKEYS received`).
    Negotiated,
    /// A definite no: the client does not know the algorithm, or the exchange failed on the
    /// client side after both agreed on the name.
    NotNegotiable,
    /// No answer: timeout, refused/dropped connection, or output we do not recognise.
    Inconclusive,
}

/// Protocol markers in the KEXINIT list (`kex-strict-*`, `ext-info-*`) are not algorithms.
pub fn is_protocol_marker(name: &str) -> bool {
    name.starts_with("kex-strict-") || name.starts_with("ext-info-")
}

fn inconclusive_set(r: Option<&SshReport>) -> HashSet<String> {
    r.map(|r| r.client_inconclusive.iter().cloned().collect())
        .unwrap_or_default()
}

/// Stop reading once an attempt's outcome is known, so the auth phase (4-5 s against some
/// servers) and the rest of the connection are never waited for.
const MAX_ATTEMPT_LOG: usize = 256 * 1024;

/// Decide the outcome from the ssh -vv stderr collected so far.
///
/// Matched against real logs: success is `kex: algorithm: <name>` followed by
/// `SSH2_MSG_NEWKEYS received`; a client that lacks the algorithm prints
/// `Unsupported KEX algorithm` / `Bad SSH2 KexAlgorithms`; a client-side failure after the
/// name was agreed prints `ssh_dispatch_run_fatal` (e.g. "memory allocation failed" for very
/// large Classic McEliece keys). Network trouble is deliberately NOT a definite no.
fn classify_attempt(kex: &str, text: &str) -> KexOutcome {
    let agreed = negotiated_kex(text).as_deref() == Some(kex);
    if agreed && text.contains("SSH2_MSG_NEWKEYS received") {
        return KexOutcome::Negotiated;
    }
    if text.contains("Unsupported KEX algorithm") || text.contains("Bad SSH2 KexAlgorithms") {
        return KexOutcome::NotNegotiable;
    }
    // The client and the server share no algorithm: a definite answer for this pair.
    if text.contains("no matching key exchange method found")
        || text.contains("kex: algorithm: (no match)")
    {
        return KexOutcome::NotNegotiable;
    }
    let network_trouble = [
        "Connection reset",
        "Connection closed",
        "Broken pipe",
        "timed out",
    ]
    .iter()
    .any(|m| text.contains(m));
    if agreed && text.contains("ssh_dispatch_run_fatal") && !network_trouble {
        return KexOutcome::NotNegotiable;
    }
    KexOutcome::Inconclusive
}

/// Read ssh's stderr until the outcome is visible (NEWKEYS received, or a fatal error), EOF,
/// or the log gets too large. The reader may stay open: we never wait for the process to exit.
async fn collect_attempt_log<R: AsyncRead + Unpin>(
    reader: R,
    text: &mut String,
) -> std::io::Result<()> {
    let mut reader = BufReader::new(reader);
    let mut buf = Vec::new();
    loop {
        buf.clear();
        if reader.read_until(b'\n', &mut buf).await? == 0 {
            return Ok(());
        }
        let line = String::from_utf8_lossy(&buf);
        text.push_str(&line);
        if line.contains("SSH2_MSG_NEWKEYS received")
            || line.contains("ssh_dispatch_run_fatal")
            || text.len() > MAX_ATTEMPT_LOG
        {
            return Ok(());
        }
    }
}

/// One attempt: run ssh with a single forced KEX, return what it logged before the outcome
/// was known (or before `timeout`), then kill it.
async fn run_ssh_attempt(
    ssh_path: &str,
    target: &Target,
    timeout: Duration,
    kex: &str,
) -> Result<String, ProbeError> {
    let mut child = Command::new(ssh_path)
        .args(ssh_args(&target.connect_host(), target.port, kex))
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| ProbeError::Protocol("ssh stderr was not captured".into()))?;
    let mut text = String::new();
    // Timeout or read error: keep whatever was collected; the classifier decides.
    let _ = tokio::time::timeout(timeout, collect_attempt_log(stderr, &mut text)).await;
    let _ = child.kill().await;
    let _ = child.wait().await;
    Ok(text)
}

/// Try one algorithm; an inconclusive first answer gets one retry after a short pause.
async fn try_kex(ssh_path: &str, target: &Target, timeout: Duration, kex: &str) -> KexOutcome {
    for attempt in 0..2 {
        if attempt > 0 {
            tokio::time::sleep(Duration::from_millis(300)).await;
        }
        if let Ok(text) = run_ssh_attempt(ssh_path, target, timeout, kex).await {
            let outcome = classify_attempt(kex, &text);
            if outcome != KexOutcome::Inconclusive {
                return outcome;
            }
        }
    }
    KexOutcome::Inconclusive
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

/// The most informative single line of ssh's output for an error message: the last non-empty
/// line, trimmed and capped so a hostile server cannot flood a report.
fn diagnostic_line(text: &str) -> String {
    let line = text
        .lines()
        .rev()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .unwrap_or("no output");
    line.chars().take(200).collect()
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
            client_inconclusive: vec![],
            client_verified: vec![],
            client_failed: vec![],
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
            client_inconclusive: vec![],
            client_verified: vec![],
            client_failed: vec![],
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

#[cfg(test)]
mod unreadable_offer_tests {
    use super::*;

    #[test]
    fn diagnostic_line_is_last_nonempty_and_capped() {
        assert_eq!(diagnostic_line(""), "no output");
        assert_eq!(diagnostic_line("a\nb\n\n  \n"), "b");
        assert_eq!(diagnostic_line(&"x".repeat(500)).len(), 200);
    }

    /// Regression: a server that accepts then hangs up used to yield an empty offer and a
    /// report saying both clients "negotiate identically". It must be an error instead.
    #[tokio::test]
    async fn server_that_hangs_up_is_an_error_not_an_empty_success() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let Ok((sock, _)) = listener.accept().await else {
                    break;
                };
                drop(sock);
            }
        });
        let opts = SshProbeOptions {
            timeout: Duration::from_secs(5),
            ssh_path: "false".to_string(),
            ..SshProbeOptions::default()
        };
        let err = probe_ssh(&Target::new("127.0.0.1", port), &opts)
            .await
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("could not read the server's key-exchange offer"),
            "{err}"
        );
    }
}

#[cfg(test)]
mod attempt_tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    // Real `ssh -vv` fragments, captured against the OQS test bench.
    const SUCCESS: &str = "debug1: kex: algorithm: ecdh-sha2-nistp256\ndebug1: kex: host key algorithm: ssh-ed25519\ndebug1: expecting SSH2_MSG_KEX_ECDH_REPLY\ndebug1: SSH2_MSG_KEX_ECDH_REPLY received\ndebug1: SSH2_MSG_NEWKEYS sent\ndebug1: expecting SSH2_MSG_NEWKEYS\ndebug1: SSH2_MSG_NEWKEYS received\n";
    const MCELIECE_FATAL: &str = "debug1: kex: algorithm: classic-mceliece-460896-sha512\ndebug1: kex: host key algorithm: ssh-ed25519\nssh_dispatch_run_fatal: Connection to 16.174.45.162 port 2222: memory allocation failed\n";
    const CLIENT_LACKS_IT: &str = "Unsupported KEX algorithm \"kyber-768-sha384\"\ncommand-line line 0: Bad SSH2 KexAlgorithms 'kyber-768-sha384'.\n";
    const REFUSED: &str = "debug1: connect to address 127.0.0.1 port 1: Connection refused\nssh: connect to host 127.0.0.1 port 1: Connection refused\n";
    const TIMED_OUT: &str = "debug1: connect to address 16.174.45.162 port 2222: Connection timed out\nssh: connect to host 16.174.45.162 port 2222: Connection timed out\n";

    #[test]
    fn completed_exchange_is_negotiated() {
        assert_eq!(
            classify_attempt("ecdh-sha2-nistp256", SUCCESS),
            KexOutcome::Negotiated
        );
    }

    #[test]
    fn newkeys_for_a_different_algorithm_does_not_count() {
        assert_eq!(
            classify_attempt("curve25519-sha256", SUCCESS),
            KexOutcome::Inconclusive
        );
    }

    #[test]
    fn name_agreement_alone_is_not_success() {
        let log = "debug1: kex: algorithm: ecdh-sha2-nistp256\ndebug1: expecting SSH2_MSG_KEX_ECDH_REPLY\n";
        assert_eq!(
            classify_attempt("ecdh-sha2-nistp256", log),
            KexOutcome::Inconclusive
        );
    }

    #[test]
    fn client_side_failure_after_agreement_is_a_definite_no() {
        assert_eq!(
            classify_attempt("classic-mceliece-460896-sha512", MCELIECE_FATAL),
            KexOutcome::NotNegotiable
        );
    }

    #[test]
    fn client_without_the_algorithm_is_a_definite_no() {
        assert_eq!(
            classify_attempt("kyber-768-sha384", CLIENT_LACKS_IT),
            KexOutcome::NotNegotiable
        );
    }

    #[test]
    fn network_trouble_is_never_a_definite_no() {
        for log in [REFUSED, TIMED_OUT, ""] {
            assert_eq!(
                classify_attempt("curve25519-sha256", log),
                KexOutcome::Inconclusive
            );
        }
        let dropped = "debug1: kex: algorithm: curve25519-sha256\nssh_dispatch_run_fatal: Connection to 1.2.3.4 port 22: Connection reset by peer\n";
        assert_eq!(
            classify_attempt("curve25519-sha256", dropped),
            KexOutcome::Inconclusive
        );
    }

    #[test]
    fn protocol_markers_are_not_algorithms() {
        assert!(is_protocol_marker("kex-strict-s-v00@openssh.com"));
        assert!(is_protocol_marker("ext-info-s"));
        assert!(!is_protocol_marker("curve25519-sha256"));
    }

    #[tokio::test]
    async fn log_collection_stops_at_newkeys_without_waiting_for_eof() {
        let (mut tx, rx) = tokio::io::duplex(4096);
        tx.write_all(SUCCESS.as_bytes()).await.unwrap();
        // tx stays open: if we waited for EOF this would hit the 2 s guard and fail.
        let mut text = String::new();
        tokio::time::timeout(Duration::from_secs(2), collect_attempt_log(rx, &mut text))
            .await
            .expect("must stop at NEWKEYS without EOF")
            .unwrap();
        assert!(text.ends_with("SSH2_MSG_NEWKEYS received\n"));
        drop(tx);
    }

    #[tokio::test]
    async fn log_collection_stops_at_a_fatal_error() {
        let (mut tx, rx) = tokio::io::duplex(4096);
        tx.write_all(MCELIECE_FATAL.as_bytes()).await.unwrap();
        let mut text = String::new();
        tokio::time::timeout(Duration::from_secs(2), collect_attempt_log(rx, &mut text))
            .await
            .expect("must stop at the fatal line")
            .unwrap();
        assert_eq!(
            classify_attempt("classic-mceliece-460896-sha512", &text),
            KexOutcome::NotNegotiable
        );
        drop(tx);
    }

    #[tokio::test]
    async fn log_collection_ends_at_eof() {
        let (mut tx, rx) = tokio::io::duplex(4096);
        tx.write_all(REFUSED.as_bytes()).await.unwrap();
        drop(tx);
        let mut text = String::new();
        collect_attempt_log(rx, &mut text).await.unwrap();
        assert_eq!(text, REFUSED);
    }

    #[test]
    fn inconclusive_algorithms_are_left_out_of_the_diff() {
        let report = |can: &[&str], inc: &[&str]| SshReport {
            target: Target::new("example.com", 22),
            server_version: None,
            server_offered_kex: vec![],
            client_can_negotiate: can.iter().map(|s| s.to_string()).collect(),
            client_inconclusive: inc.iter().map(|s| s.to_string()).collect(),
            client_verified: vec![],
            client_failed: vec![],
            client_version: None,
        };
        let v = report(&["a"], &["b"]);
        let e = report(&["a", "b", "c"], &["d"]);
        let v_set: HashSet<String> = v.client_can_negotiate.iter().cloned().collect();
        let e_set: HashSet<String> = e.client_can_negotiate.iter().cloned().collect();
        let v_inc = inconclusive_set(Some(&v));
        let only_e: Vec<&String> = e_set
            .difference(&v_set)
            .filter(|k| !v_inc.contains(*k))
            .collect();
        // "b" is only on the experimental side, but vanilla could not be tested on it.
        assert_eq!(only_e, vec![&"c".to_string()]);
    }
}

#[cfg(test)]
mod support_check_tests {
    use super::*;

    fn names(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn parses_ssh_dash_q_output() {
        let set = parse_query_list(
            "curve25519-sha256\n  mlkem768x25519-sha256 \n\nsntrup761x25519-sha512@openssh.com\n",
        );
        assert_eq!(set.len(), 3);
        assert!(set.contains("mlkem768x25519-sha256"));
        assert!(parse_query_list("").is_empty());
    }

    #[test]
    fn pq_kex_names() {
        for n in [
            "mlkem768x25519-sha256",
            "sntrup761x25519-sha512@openssh.com",
            "kyber-768-sha384",
            "frodokem-640-aes-sha256",
            "bike-l1-sha512",
            "classic-mceliece-348864-sha256",
        ] {
            assert!(is_pq_kex_name(n), "{n}");
        }
        for n in [
            "curve25519-sha256",
            "ecdh-sha2-nistp256",
            "diffie-hellman-group14-sha256",
        ] {
            assert!(!is_pq_kex_name(n), "{n}");
        }
    }

    #[test]
    fn verification_picks_pq_usable_names_by_priority_and_caps_them() {
        let offered = names(&[
            "curve25519-sha256",
            "kyber-512-sha256",
            "sntrup761x25519-sha512@openssh.com",
            "mlkem768x25519-sha256",
            "frodokem-640-aes-sha256",
            "mlkem1024-sha384",
            "bike-l1-sha512",
        ]);
        // the client lacks frodokem; curve25519 is not post-quantum
        let usable: BTreeSet<String> = offered
            .iter()
            .filter(|k| k.as_str() != "frodokem-640-aes-sha256")
            .cloned()
            .collect();
        assert_eq!(
            pick_to_verify(&offered, &usable, 10),
            names(&[
                "mlkem768x25519-sha256",
                "mlkem1024-sha384",
                "sntrup761x25519-sha512@openssh.com",
                "kyber-512-sha256",
                "bike-l1-sha512",
            ])
        );
        assert_eq!(pick_to_verify(&offered, &usable, 2).len(), 2);
        assert!(pick_to_verify(&offered, &usable, 0).is_empty());
        assert!(pick_to_verify(&offered, &BTreeSet::new(), 5).is_empty());
    }

    #[test]
    fn default_verification_cap_is_small() {
        assert_eq!(SshProbeOptions::default().max_verify, 8);
    }

    #[tokio::test]
    async fn missing_ssh_binary_means_no_local_support_list() {
        assert!(
            query_client_kex("/nonexistent/ssh-for-test", Duration::from_secs(2))
                .await
                .is_none()
        );
    }
}

#[cfg(test)]
mod pacing_tests {
    use super::*;

    #[test]
    fn handshake_tests_are_sequential_and_paced_by_default() {
        let o = SshProbeOptions::default();
        assert_eq!(o.max_parallel, 1);
        assert!(o.pace >= Duration::from_secs(1));
    }
}

#[cfg(test)]
mod no_common_algorithm_tests {
    use super::*;

    // Real output: stock OpenSSH 9.6 forced to sntrup761x25519-sha512@openssh.com against the
    // OQS test bench.
    const NO_COMMON: &str = "debug1: kex: algorithm: (no match)\nUnable to negotiate with 16.174.45.162 port 2222: no matching key exchange method found. Their offer: curve25519-sha256,ecdh-sha2-nistp256\n";

    #[test]
    fn no_common_algorithm_is_a_definite_no() {
        assert_eq!(
            classify_attempt("sntrup761x25519-sha512@openssh.com", NO_COMMON),
            KexOutcome::NotNegotiable
        );
    }
}
