//! A few plain lines on top of the JSON report.
//!
//! The report is written for programs: per-side results, diffs, inconclusive lists. A small
//! local model reading it raw often answers from the wrong field (for example, reading the KEMs
//! the client *offered* as what the server *supports*). The summary states the answer the way a
//! person would, from the same data, and the full report follows it for anything else.

use pqc_probe_core::{is_pq_group_name, is_pq_signature_name, Report, SshClientResult, TlsReport};

fn is_pq_kex(name: &str) -> bool {
    is_pq_group_name(name) || name.to_ascii_lowercase().contains("mceliece")
}

/// YES / NO only when something was actually measured. A closed port or a non-TLS service
/// completes no handshake at all; calling that "NO" would hand the agent a confident wrong
/// answer to pass on.
fn verdict(pq: bool, measured: bool) -> &'static str {
    match (pq, measured) {
        (true, _) => "YES",
        (false, true) => "NO",
        (false, false) => {
            "UNKNOWN (nothing completed a handshake: closed or filtered port, or not this protocol)"
        }
    }
}

fn tls_side(label: &str, r: &TlsReport) -> (bool, bool, String) {
    let pq: Vec<&str> = r
        .kems_tried
        .iter()
        .filter(|k| k.handshake_succeeded && is_pq_group_name(&k.offered))
        .map(|k| k.negotiated.as_deref().unwrap_or(k.offered.as_str()))
        .collect();
    let classical: Vec<&str> = r
        .kems_tried
        .iter()
        .filter(|k| k.handshake_succeeded && !is_pq_group_name(&k.offered))
        .map(|k| k.offered.as_str())
        .collect();
    let groups = if pq.is_empty() {
        format!(
            "no post-quantum group negotiated (classical groups that worked: {})",
            list_or_none(&classical)
        )
    } else {
        format!("post-quantum groups negotiated: {}", pq.join(", "))
    };
    let cert = match &r.cert_sig_alg {
        Some(alg) => format!(
            "certificate signature {alg} ({})",
            if is_pq_signature_name(alg) {
                "post-quantum"
            } else {
                "classical"
            }
        ),
        None => "certificate signature unknown".to_string(),
    };
    let measured = !pq.is_empty() || !classical.is_empty();
    (
        !pq.is_empty(),
        measured,
        format!("- {label}: {groups}; {cert}"),
    )
}

fn list_or_none(v: &[&str]) -> String {
    if v.is_empty() {
        "none".to_string()
    } else {
        v.join(", ")
    }
}

fn ssh_side(label: &str, r: &SshClientResult) -> String {
    let verified: Vec<&str> = r
        .client_verified
        .iter()
        .filter(|a| is_pq_kex(a))
        .map(String::as_str)
        .collect();
    format!(
        "- {label}: post-quantum key exchanges completed in a real handshake: {}",
        list_or_none(&verified)
    )
}

pub fn summarize(report: &Report) -> String {
    let host = &report.target.host;
    let mut out = Vec::new();

    if let Some(tls) = &report.tls {
        let port = report.target.tls_port.unwrap_or(443);
        let mut any_pq = false;
        let mut measured = false;
        let mut lines = Vec::new();
        for (label, side) in [
            ("stock client", &tls.vanilla),
            ("experimental PQ client", &tls.experimental),
        ] {
            if let Some(r) = side {
                let (pq, ok, line) = tls_side(label, r);
                any_pq |= pq;
                measured |= ok;
                lines.push(line);
            }
        }
        out.push(format!(
            "TLS {host}:{port}: post-quantum key exchange supported: {}",
            verdict(any_pq, measured)
        ));
        out.extend(lines);
        if let Some(d) = &tls.diff {
            if !d.only_experimental.is_empty() {
                out.push(format!(
                    "- only the experimental client got: {}",
                    d.only_experimental.join(", ")
                ));
            }
        }
        if tls.vanilla_pq_capable == Some(true) && tls.experimental.is_some() {
            out.push(
                "- note: the stock client already speaks PQ, so the stock-vs-experimental diff says little about the server"
                    .to_string(),
            );
        }
        push_errors(&mut out, &tls.errors.vanilla, &tls.errors.experimental);
    }

    if let Some(ssh) = &report.ssh {
        let port = report.target.ssh_port.unwrap_or(22);
        let offered: Vec<&str> = ssh
            .vanilla
            .iter()
            .chain(ssh.experimental.iter())
            .flat_map(|r| r.server_offered_kex.iter())
            .filter(|a| is_pq_kex(a))
            .map(String::as_str)
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect();
        let measured = ssh
            .vanilla
            .iter()
            .chain(ssh.experimental.iter())
            .any(|r| !r.server_offered_kex.is_empty());
        out.push(format!(
            "SSH {host}:{port}: server offers post-quantum key exchange: {}",
            verdict(!offered.is_empty(), measured)
        ));
        out.push(format!(
            "- post-quantum algorithms the server offers: {}",
            list_or_none(&offered)
        ));
        if let Some(r) = &ssh.vanilla {
            out.push(ssh_side("stock ssh client", r));
        }
        if let Some(r) = &ssh.experimental {
            out.push(ssh_side("experimental OQS ssh client", r));
        }
        push_errors(&mut out, &ssh.errors.vanilla, &ssh.errors.experimental);
    }

    out.push("Full JSON report (schema v1) follows.".to_string());
    out.join("\n")
}

fn push_errors(out: &mut Vec<String>, vanilla: &Option<String>, experimental: &Option<String>) {
    if let Some(e) = vanilla {
        out.push(format!("- stock client failed: {e}"));
    }
    if let Some(e) = experimental {
        out.push(format!("- experimental client failed: {e}"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report(json: serde_json::Value) -> Report {
        serde_json::from_value(json).expect("valid report")
    }

    fn base() -> serde_json::Value {
        serde_json::json!({
            "schema_version": 1,
            "tool": {"name": "pqc-probe", "version": "0.2.0"},
            "generated_at": "2026-11-22T00:00:00Z",
            "target": {"input": "example.com", "host": "example.com", "tls_port": 443, "ssh_port": null},
            "request": {"protocol": "tls", "mode": "vanilla"},
            "tls": null,
            "ssh": null
        })
    }

    #[test]
    fn says_yes_when_a_pq_group_completes_a_handshake() {
        let mut j = base();
        j["tls"] = serde_json::json!({
            "vanilla": {
                "protocol_version": "TLSv1.3", "cipher": null,
                "kems_tried": [
                    {"offered": "X25519MLKEM768", "negotiated": "X25519MLKEM768", "handshake_succeeded": true},
                    {"offered": "X25519", "negotiated": "X25519", "handshake_succeeded": true}
                ],
                "cert_sig_alg": "ecdsa-with-SHA256", "peer_sig_alg": null
            },
            "experimental": null, "diff": null, "vanilla_pq_capable": true,
            "errors": {"vanilla": null, "experimental": null}
        });
        let s = summarize(&report(j));
        assert!(
            s.starts_with("TLS example.com:443: post-quantum key exchange supported: YES"),
            "{s}"
        );
        assert!(s.contains("X25519MLKEM768"), "{s}");
        assert!(s.contains("ecdsa-with-SHA256 (classical)"), "{s}");
    }

    #[test]
    fn says_no_when_only_classical_groups_work() {
        let mut j = base();
        j["tls"] = serde_json::json!({
            "vanilla": {
                "protocol_version": "TLSv1.3", "cipher": null,
                "kems_tried": [
                    {"offered": "X25519MLKEM768", "negotiated": null, "handshake_succeeded": false},
                    {"offered": "X25519", "negotiated": "X25519", "handshake_succeeded": true}
                ],
                "cert_sig_alg": null, "peer_sig_alg": null
            },
            "experimental": null, "diff": null, "vanilla_pq_capable": false,
            "errors": {"vanilla": null, "experimental": null}
        });
        let s = summarize(&report(j));
        assert!(s.contains("supported: NO"), "{s}");
        assert!(s.contains("classical groups that worked: X25519"), "{s}");
    }

    #[test]
    fn says_unknown_when_no_handshake_completed() {
        let mut j = base();
        j["tls"] = serde_json::json!({
            "vanilla": {
                "protocol_version": null, "cipher": null,
                "kems_tried": [
                    {"offered": "X25519MLKEM768", "negotiated": null, "handshake_succeeded": false},
                    {"offered": "X25519", "negotiated": null, "handshake_succeeded": false}
                ],
                "cert_sig_alg": null, "peer_sig_alg": null
            },
            "experimental": null, "diff": null, "vanilla_pq_capable": false,
            "errors": {"vanilla": null, "experimental": null}
        });
        let s = summarize(&report(j));
        assert!(s.contains("supported: UNKNOWN"), "{s}");
        assert!(!s.contains("supported: NO"), "{s}");
    }

    #[test]
    fn reports_ssh_offer_and_side_errors() {
        let mut j = base();
        j["target"]["tls_port"] = serde_json::Value::Null;
        j["target"]["ssh_port"] = serde_json::json!(22);
        j["ssh"] = serde_json::json!({
            "vanilla": {
                "client_version": "OpenSSH_9.9", "server_version": "SSH-2.0-OpenSSH_9.9",
                "server_offered_kex": ["mlkem768x25519-sha256", "curve25519-sha256", "kex-strict-s-v00@openssh.com"],
                "client_can_negotiate": ["mlkem768x25519-sha256", "curve25519-sha256"],
                "client_verified": ["mlkem768x25519-sha256"]
            },
            "experimental": null, "diff": null,
            "errors": {"vanilla": null, "experimental": "the probe timed out"}
        });
        let s = summarize(&report(j));
        assert!(
            s.contains("SSH example.com:22: server offers post-quantum key exchange: YES"),
            "{s}"
        );
        assert!(s.contains("offers: mlkem768x25519-sha256"), "{s}");
        assert!(
            s.contains("experimental client failed: the probe timed out"),
            "{s}"
        );
    }
}
