//! Server-rendered HTML: no JavaScript, no inline styles and no template engine. Pages are built
//! from strings, and every value that did not come from this file goes through [`esc`]:
//! certificate subjects, SSH version strings and algorithm names are all chosen by the server
//! being scanned, so they are hostile input.
//!
//! Table cells are passed around as already-safe HTML strings; build them with [`esc`] or from
//! literals in this file only.

use crate::model::{JobStatus, JobView};
use pqc_probe_core::report::SideErrors;
use pqc_probe_core::{
    is_pq_group_name, ModeSelection, ProtocolSelection, Report, SshClientResult, SshSection,
    TlsReport, TlsSection,
};

const CSS: &str = r#":root{--bg:#fafafa;--fg:#1b1f23;--muted:#5b6570;--line:#d8dde3;--card:#fff;--accent:#1f6feb;--ok:#1a7f37;--bad:#b42318;--warn:#9a6700;--pq:#6f42c1}
@media (prefers-color-scheme:dark){:root{--bg:#0f1318;--fg:#e6e9ed;--muted:#9aa5b1;--line:#2b333d;--card:#161b22;--accent:#58a6ff;--ok:#3fb950;--bad:#f85149;--warn:#d29922;--pq:#b392f0}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:16px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
main{max-width:60rem;margin:0 auto;padding:1rem}
header{padding:.5rem 0 1rem}
.brand{font-weight:700;color:var(--fg);text-decoration:none;font-size:1.1rem}
h1{font-size:1.6rem;margin:.5rem 0}
h2{font-size:1.2rem;margin:1.5rem 0 .5rem}
a{color:var(--accent)}
.meta,.hint,footer{color:var(--muted);font-size:.9rem}
footer{margin-top:2rem;border-top:1px solid var(--line);padding-top:.75rem}
form{display:grid;gap:.75rem;background:var(--card);border:1px solid var(--line);border-radius:8px;padding:1rem}
label{display:grid;gap:.25rem;font-weight:600}
input,select,button{font:inherit;padding:.5rem;border:1px solid var(--line);border-radius:6px;background:var(--bg);color:var(--fg)}
button{background:var(--accent);color:#fff;border-color:var(--accent);cursor:pointer;font-weight:600}
.row{display:grid;grid-template-columns:repeat(auto-fit,minmax(10rem,1fr));gap:.75rem}
.error{border:1px solid var(--bad);color:var(--bad);border-radius:6px;padding:.5rem .75rem}
.note{border:1px solid var(--warn);color:var(--warn);border-radius:6px;padding:.5rem .75rem}
.scroll{overflow-x:auto}
table{border-collapse:collapse;width:100%;margin:.5rem 0}
th,td{border-bottom:1px solid var(--line);padding:.35rem .5rem;text-align:left;vertical-align:top;font-size:.92rem}
th{color:var(--muted);font-weight:600}
code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.88em;word-break:break-all}
.pq{display:inline-block;margin-left:.4rem;padding:0 .35rem;border:1px solid var(--pq);color:var(--pq);border-radius:4px;font-size:.75rem;font-weight:700}
.ok{color:var(--ok);font-weight:600}.bad{color:var(--bad);font-weight:600}.warn{color:var(--warn);font-weight:600}.no{color:var(--muted)}
"#;

pub fn stylesheet() -> &'static str {
    CSS
}

/// Escape text for use in HTML element content or a quoted attribute value. Control characters
/// are replaced as well, so a hostile string cannot smuggle them into the page.
pub fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c if c.is_control() && c != '\n' => out.push('\u{fffd}'),
            c => out.push(c),
        }
    }
    out
}

fn code(s: &str) -> String {
    format!("<code>{}</code>", esc(s))
}

fn pq_badge(name: &str) -> &'static str {
    if is_pq_group_name(name) {
        "<span class=\"pq\">PQ</span>"
    } else {
        ""
    }
}

fn protocol_label(p: ProtocolSelection) -> &'static str {
    match p {
        ProtocolSelection::Tls => "tls",
        ProtocolSelection::Ssh => "ssh",
        ProtocolSelection::Both => "both",
    }
}

fn mode_label(m: ModeSelection) -> &'static str {
    match m {
        ModeSelection::Vanilla => "vanilla",
        ModeSelection::Experimental => "experimental",
        ModeSelection::Both => "both",
    }
}

pub fn page(title: &str, refresh_secs: Option<u32>, body: &str) -> String {
    let refresh = refresh_secs
        .map(|s| format!("<meta http-equiv=\"refresh\" content=\"{s}\">"))
        .unwrap_or_default();
    format!(
        "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">\
<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">{refresh}\
<title>{}</title><link rel=\"stylesheet\" href=\"/static/style.css\"></head>\
<body><main><header><a class=\"brand\" href=\"/\">pqc-probe</a></header>{body}\
<footer>Probes connect to the target from this server and read what it offers. \
Results are kept for a limited time.</footer></main></body></html>",
        esc(title)
    )
}

/// What the visitor typed, kept so the form can be shown again after an error.
#[derive(Debug, Clone, Default)]
pub struct FormValues {
    pub target: String,
    pub protocol: String,
    pub mode: String,
    pub tls_port: String,
    pub ssh_port: String,
}

fn options(current: &str, items: &[(&str, &str)]) -> String {
    items
        .iter()
        .map(|(v, label)| {
            let sel = if *v == current { " selected" } else { "" };
            format!("<option value=\"{v}\"{sel}>{label}</option>")
        })
        .collect()
}

pub fn index_page(form: &FormValues, error: Option<&str>, offers: &str) -> String {
    let protocol = if form.protocol.is_empty() {
        "tls"
    } else {
        form.protocol.as_str()
    };
    let err = error
        .map(|e| format!("<p class=\"error\" role=\"alert\">{}</p>", esc(e)))
        .unwrap_or_default();
    let body = format!(
        "<h1>Which post-quantum algorithms does a server support?</h1>\
<p>Enter a host. The probe compares a stock client with an experimental post-quantum build.</p>{err}\
<form method=\"post\" action=\"/probe\">\
<label>Target<input name=\"target\" value=\"{target}\" maxlength=\"300\" required \
placeholder=\"example.com or example.com:8443\" autocomplete=\"off\"></label>\
<div class=\"row\">\
<label>Protocol<select name=\"protocol\">{protocols}</select></label>\
<label>Mode<select name=\"mode\">{modes}</select></label></div>\
<div class=\"row\">\
<label>TLS port (optional)<input name=\"tls_port\" value=\"{tls_port}\" maxlength=\"5\" inputmode=\"numeric\"></label>\
<label>SSH port (optional)<input name=\"ssh_port\" value=\"{ssh_port}\" maxlength=\"5\" inputmode=\"numeric\"></label></div>\
<button type=\"submit\">Probe</button></form>\
<p class=\"hint\">Available here: {offers}</p>",
        target = esc(&form.target),
        protocols = options(
            protocol,
            &[("tls", "TLS"), ("ssh", "SSH"), ("both", "TLS and SSH")]
        ),
        modes = options(
            &form.mode,
            &[
                ("", "Default"),
                ("vanilla", "Stock client only"),
                ("experimental", "Experimental client only"),
                ("both", "Both, compared"),
            ]
        ),
        tls_port = esc(&form.tls_port),
        ssh_port = esc(&form.ssh_port),
        offers = esc(offers),
    );
    page("pqc-probe", None, &body)
}

pub fn error_page(title: &str, message: &str) -> String {
    page(
        title,
        None,
        &format!(
            "<h1>{}</h1><p class=\"error\" role=\"alert\">{}</p><p><a href=\"/\">Start a new probe</a></p>",
            esc(title),
            esc(message)
        ),
    )
}

fn status_label(s: JobStatus) -> &'static str {
    match s {
        JobStatus::Queued => "queued",
        JobStatus::Running => "running",
        JobStatus::Succeeded => "finished",
        JobStatus::Failed => "failed",
        JobStatus::TimedOut => "timed out",
    }
}

pub fn job_page(view: &JobView, report: Option<&Report>) -> String {
    match view.status {
        JobStatus::Queued | JobStatus::Running => page(
            "Probing...",
            Some(3),
            &format!(
                "<h1>Probing {}</h1><p>Status: {}. This page refreshes every few seconds.</p>\
<p class=\"hint\">Probing a server with SSH takes several seconds because the handshakes are paced.</p>",
                esc(&view.target),
                status_label(view.status)
            ),
        ),
        JobStatus::Succeeded => match report {
            Some(r) => page(
                &format!("Report for {}", r.target.host),
                None,
                &report_html(r, &format!("/api/v1/probes/{}/report", view.id)),
            ),
            None => error_page(
                "Report no longer available",
                "The probe finished, but its report has expired. Start a new probe.",
            ),
        },
        JobStatus::Failed | JobStatus::TimedOut => error_page(
            &format!("Probe of {} {}", view.target, status_label(view.status)),
            view.error.as_deref().unwrap_or("The probe did not complete."),
        ),
    }
}

fn table(head: &[&str], rows: &[Vec<String>]) -> String {
    let mut s = String::from("<div class=\"scroll\"><table><thead><tr>");
    for h in head {
        s.push_str(&format!("<th>{h}</th>"));
    }
    s.push_str("</tr></thead><tbody>");
    for row in rows {
        s.push_str("<tr>");
        for cell in row {
            s.push_str(&format!("<td>{cell}</td>"));
        }
        s.push_str("</tr>");
    }
    s.push_str("</tbody></table></div>");
    s
}

fn dash() -> String {
    "<span class=\"no\">-</span>".to_string()
}

fn opt(s: Option<&str>) -> String {
    s.map(esc).unwrap_or_else(dash)
}

fn side_errors(e: &SideErrors) -> String {
    let mut s = String::new();
    for (label, msg) in [
        ("Stock client", &e.vanilla),
        ("Experimental client", &e.experimental),
    ] {
        if let Some(m) = msg {
            s.push_str(&format!(
                "<p class=\"error\"><strong>{label}:</strong> {}</p>",
                esc(m)
            ));
        }
    }
    s
}

fn name_list(names: &[String]) -> String {
    if names.is_empty() {
        return "none".to_string();
    }
    names.iter().map(|n| code(n)).collect::<Vec<_>>().join(", ")
}

pub fn report_html(r: &Report, json_url: &str) -> String {
    let mut s = format!(
        "<h1>Report for {}</h1><p class=\"meta\">Requested: {} / {} mode. Generated {}. \
pqc-probe {}. <a href=\"{}\">JSON</a></p>",
        esc(&r.target.host),
        protocol_label(r.request.protocol),
        mode_label(r.request.mode),
        esc(&r.generated_at),
        esc(&r.tool.version),
        esc(json_url)
    );
    if r.tls.is_none() && r.ssh.is_none() {
        s.push_str("<p>This report has no results.</p>");
    }
    if let Some(t) = &r.tls {
        s.push_str(&tls_html(r.target.tls_port, t));
    }
    if let Some(x) = &r.ssh {
        s.push_str(&ssh_html(r.target.ssh_port, x));
    }
    s
}

fn tls_summary_row(label: &str, r: Option<&TlsReport>) -> Vec<String> {
    match r {
        None => vec![label.to_string(), dash(), dash(), dash()],
        Some(r) => vec![
            label.to_string(),
            opt(r.protocol_version.as_deref()),
            opt(r.cipher.as_deref()),
            opt(r.openssl_version.as_deref()),
        ],
    }
}

fn group_cell(r: Option<&TlsReport>, name: &str) -> String {
    match r {
        None => dash(),
        Some(r) => match r.kems_tried.iter().find(|k| k.offered == name) {
            Some(k) if k.handshake_succeeded => "<span class=\"ok\">negotiated</span>".to_string(),
            Some(_) => "<span class=\"no\">no</span>".to_string(),
            None => dash(),
        },
    }
}

fn tls_html(port: Option<u16>, t: &TlsSection) -> String {
    let heading = match port {
        Some(p) => format!("TLS (port {p})"),
        None => "TLS".to_string(),
    };
    let mut s = format!("<section><h2>{heading}</h2>");
    s.push_str(&side_errors(&t.errors));
    if t.vanilla_pq_capable == Some(true) {
        s.push_str(
            "<p class=\"note\">The stock client on this server already negotiates post-quantum \
groups, so comparing it with the experimental client says little about the target.</p>",
        );
    }
    let (v, e) = (t.vanilla.as_ref(), t.experimental.as_ref());
    s.push_str(&table(
        &["Client", "Protocol", "Cipher", "OpenSSL"],
        &[
            tls_summary_row("Stock", v),
            tls_summary_row("Experimental", e),
        ],
    ));

    let mut names: Vec<&str> = Vec::new();
    for r in [v, e].into_iter().flatten() {
        for k in &r.kems_tried {
            if !names.contains(&k.offered.as_str()) {
                names.push(&k.offered);
            }
        }
    }
    let rows: Vec<Vec<String>> = names
        .iter()
        .map(|n| {
            vec![
                format!("{}{}", code(n), pq_badge(n)),
                group_cell(v, n),
                group_cell(e, n),
            ]
        })
        .collect();
    if !rows.is_empty() {
        s.push_str("<h3>Key exchange groups</h3>");
        s.push_str(&table(&["Group", "Stock", "Experimental"], &rows));
    }
    if let Some(d) = &t.diff {
        s.push_str(&format!(
            "<p>Negotiated only by the experimental client: {}.<br>Only by the stock client: {}.</p>",
            name_list(&d.only_experimental),
            name_list(&d.only_vanilla)
        ));
    }

    if let Some(chain) = e.or(v).map(|r| &r.cert_chain).filter(|c| !c.is_empty()) {
        let rows: Vec<Vec<String>> = chain
            .iter()
            .map(|c| {
                let key = match (&c.public_key_type, c.public_key_bits) {
                    (Some(t), Some(b)) => format!("{} ({b} bits)", esc(t)),
                    (Some(t), None) => esc(t),
                    (None, _) => dash(),
                };
                vec![
                    c.depth.to_string(),
                    esc(&c.subject),
                    esc(&c.issuer),
                    opt(c.signature_algorithm.as_deref()),
                    key,
                    opt(c.not_after.as_deref()),
                    if c.post_quantum {
                        "<span class=\"pq\">PQ</span>".to_string()
                    } else {
                        "<span class=\"no\">classical</span>".to_string()
                    },
                ]
            })
            .collect();
        s.push_str("<h3>Certificate chain</h3>");
        s.push_str(&table(
            &[
                "Depth",
                "Subject",
                "Issuer",
                "Signature",
                "Key",
                "Expires",
                "Type",
            ],
            &rows,
        ));
    }
    s.push_str("</section>");
    s
}

/// (css class, label) for what one ssh client did with one of the server's algorithms.
pub fn ssh_status(c: &SshClientResult, alg: &str) -> (&'static str, &'static str) {
    let has = |list: &Vec<String>| list.iter().any(|a| a == alg);
    if has(&c.client_verified) {
        ("ok", "verified")
    } else if has(&c.client_can_negotiate) {
        ("ok", "supported")
    } else if has(&c.client_failed) {
        ("bad", "failed")
    } else if has(&c.client_inconclusive) {
        ("warn", "inconclusive")
    } else {
        ("no", "no")
    }
}

fn ssh_cell(c: Option<&SshClientResult>, alg: &str) -> String {
    match c {
        None => dash(),
        Some(c) => {
            let (class, label) = ssh_status(c, alg);
            format!("<span class=\"{class}\">{label}</span>")
        }
    }
}

fn ssh_html(port: Option<u16>, x: &SshSection) -> String {
    let heading = match port {
        Some(p) => format!("SSH (port {p})"),
        None => "SSH".to_string(),
    };
    let mut s = format!("<section><h2>{heading}</h2>");
    s.push_str(&side_errors(&x.errors));
    let (v, e) = (x.vanilla.as_ref(), x.experimental.as_ref());
    if let Some(any) = e.or(v) {
        s.push_str(&format!(
            "<p>Server software: {}. Key exchange algorithms offered: {}.</p>",
            opt(any.server_version.as_deref()),
            any.server_offered_kex.len()
        ));
        let mut algs: Vec<&String> = any.server_offered_kex.iter().collect();
        algs.sort_by_key(|a| !is_pq_group_name(a));
        let rows: Vec<Vec<String>> = algs
            .iter()
            .map(|a| {
                vec![
                    format!("{}{}", code(a), pq_badge(a)),
                    ssh_cell(v, a),
                    ssh_cell(e, a),
                ]
            })
            .collect();
        s.push_str(&table(
            &["Algorithm", "Stock ssh", "Experimental ssh"],
            &rows,
        ));
        s.push_str(
            "<p class=\"hint\">verified: a real key exchange with this server completed. \
supported: the client implements it, but it was not tried (post-quantum algorithms are tried, \
the rest are not, to stay polite to the server). inconclusive: the test could not tell.</p>",
        );
    }
    if let Some(d) = &x.diff {
        let only_exp: Vec<String> = d
            .only_experimental
            .iter()
            .map(|a| match d.mainline_since.get(a) {
                Some(ver) => format!("{} (stock OpenSSH since {})", code(a), esc(ver)),
                None => code(a),
            })
            .collect();
        s.push_str(&format!(
            "<p>Only the experimental client can negotiate: {}.<br>Only the stock client: {}.</p>",
            if only_exp.is_empty() {
                "none".to_string()
            } else {
                only_exp.join(", ")
            },
            name_list(&d.only_vanilla)
        ));
    }
    s.push_str("</section>");
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use pqc_probe_core::report::SideErrors;
    use pqc_probe_core::{CertInfo, KemResult};
    use pqc_probe_core::{ReportTarget, RequestInfo, SshKexDiff};

    const EVIL: &str = "<script>alert(1)</script>\"><img src=x onerror=alert(1)>";

    /// The page must contain no tag that came from the hostile string. Text such as
    /// `onerror=alert(1)` is harmless once the `<` and `"` around it are escaped.
    fn assert_inert(html: &str) {
        assert!(!html.contains(EVIL), "raw hostile string in:\n{html}");
        for bad in ["<script", "<img", "<b>", "</b>"] {
            assert!(!html.contains(bad), "unescaped {bad:?} in:\n{html}");
        }
    }

    fn hostile_tls() -> TlsReport {
        TlsReport {
            protocol_version: Some(EVIL.into()),
            cipher: Some(EVIL.into()),
            kems_tried: vec![
                KemResult {
                    offered: "X25519".into(),
                    negotiated: Some("X25519".into()),
                    handshake_succeeded: true,
                },
                KemResult {
                    offered: "X25519MLKEM768".into(),
                    negotiated: None,
                    handshake_succeeded: false,
                },
                KemResult {
                    offered: "<b>evil</b>".into(),
                    negotiated: None,
                    handshake_succeeded: false,
                },
            ],
            cert_sig_alg: None,
            peer_sig_alg: None,
            cert_chain: vec![CertInfo {
                depth: 0,
                subject: EVIL.into(),
                issuer: EVIL.into(),
                signature_algorithm: Some(EVIL.into()),
                public_key_type: Some(EVIL.into()),
                public_key_bits: Some(256),
                not_before: None,
                not_after: Some(EVIL.into()),
                self_signed: false,
                post_quantum: false,
            }],
            openssl_version: Some(EVIL.into()),
        }
    }

    fn hostile_ssh() -> SshClientResult {
        SshClientResult {
            client_version: Some(EVIL.into()),
            server_version: Some(EVIL.into()),
            server_offered_kex: vec![
                "curve25519-sha256".into(),
                "mlkem768x25519-sha256".into(),
                "<b>x</b>".into(),
            ],
            client_can_negotiate: vec!["curve25519-sha256".into(), "mlkem768x25519-sha256".into()],
            client_inconclusive: vec![],
            client_verified: vec!["mlkem768x25519-sha256".into()],
            client_failed: vec![],
        }
    }

    fn hostile_report() -> Report {
        let mut mainline = std::collections::BTreeMap::new();
        mainline.insert("<b>x</b>".to_string(), EVIL.to_string());
        Report::new(
            ReportTarget {
                input: EVIL.into(),
                host: EVIL.into(),
                tls_port: Some(443),
                ssh_port: Some(22),
            },
            RequestInfo {
                protocol: ProtocolSelection::Both,
                mode: ModeSelection::Both,
            },
        )
        .with_tls(Some(TlsSection {
            vanilla: Some(hostile_tls()),
            experimental: Some(hostile_tls()),
            diff: Some(Default::default()),
            vanilla_pq_capable: Some(true),
            errors: SideErrors {
                vanilla: Some(EVIL.into()),
                experimental: None,
            },
        }))
        .with_ssh(Some(SshSection {
            vanilla: Some(hostile_ssh()),
            experimental: Some(hostile_ssh()),
            diff: Some(SshKexDiff {
                only_experimental: vec!["<b>x</b>".into()],
                mainline_since: mainline,
                ..Default::default()
            }),
            errors: SideErrors::default(),
        }))
    }

    #[test]
    fn escaping_covers_markup_quotes_and_control_characters() {
        assert_eq!(esc("a<b>&\"'"), "a&lt;b&gt;&amp;&quot;&#39;");
        assert_eq!(esc("a\u{0}b\u{7}c"), "a\u{fffd}b\u{fffd}c");
        assert_eq!(esc("plain"), "plain");
    }

    #[test]
    fn nothing_a_scanned_server_controls_reaches_the_page_unescaped() {
        let html = report_html(&hostile_report(), "/api/v1/probes/abc/report");
        assert_inert(&html);
        assert!(html.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
    }

    #[test]
    fn the_job_pages_escape_the_target_and_the_error() {
        let mut view = JobView {
            id: "0123456789abcdef0123456789abcdef".into(),
            status: JobStatus::Failed,
            target: EVIL.into(),
            created_at: "t".into(),
            finished_at: None,
            error: Some(EVIL.into()),
            report_url: None,
        };
        assert_inert(&job_page(&view, None));
        view.status = JobStatus::Running;
        assert_inert(&job_page(&view, None));
        view.status = JobStatus::Succeeded;
        assert_inert(&job_page(&view, Some(&hostile_report())));
    }

    #[test]
    fn only_unfinished_jobs_refresh() {
        let mut view = JobView {
            id: "0123456789abcdef0123456789abcdef".into(),
            status: JobStatus::Queued,
            target: "example.com".into(),
            created_at: "t".into(),
            finished_at: None,
            error: None,
            report_url: None,
        };
        assert!(job_page(&view, None).contains("http-equiv=\"refresh\""));
        view.status = JobStatus::Running;
        assert!(job_page(&view, None).contains("http-equiv=\"refresh\""));
        for done in [JobStatus::Succeeded, JobStatus::Failed, JobStatus::TimedOut] {
            view.status = done;
            assert!(
                !job_page(&view, None).contains("http-equiv=\"refresh\""),
                "{done:?}"
            );
        }
    }

    #[test]
    fn the_form_is_shown_again_with_escaped_values() {
        let form = FormValues {
            target: EVIL.into(),
            tls_port: EVIL.into(),
            ssh_port: EVIL.into(),
            protocol: "ssh".into(),
            mode: "both".into(),
        };
        let html = index_page(&form, Some(EVIL), EVIL);
        assert_inert(&html);
        assert!(html.contains("<option value=\"ssh\" selected>"));
        assert!(html.contains("<option value=\"both\" selected>"));
    }

    #[test]
    fn pages_load_no_script_and_use_no_inline_style() {
        let html = index_page(&FormValues::default(), None, "x");
        assert!(!html.contains("<script"));
        assert!(!html.contains("style=\""));
        assert!(!html.contains("<style"));
        assert!(html.contains("href=\"/static/style.css\""));
    }

    #[test]
    fn ssh_status_prefers_the_strongest_statement() {
        let c = hostile_ssh();
        assert_eq!(ssh_status(&c, "mlkem768x25519-sha256"), ("ok", "verified"));
        assert_eq!(ssh_status(&c, "curve25519-sha256"), ("ok", "supported"));
        assert_eq!(ssh_status(&c, "something-else"), ("no", "no"));
        let mut c2 = hostile_ssh();
        c2.client_failed = vec!["a".into()];
        c2.client_inconclusive = vec!["b".into()];
        assert_eq!(ssh_status(&c2, "a"), ("bad", "failed"));
        assert_eq!(ssh_status(&c2, "b"), ("warn", "inconclusive"));
    }

    #[test]
    fn post_quantum_rows_are_flagged_and_listed_first() {
        let html = report_html(&hostile_report(), "/x");
        let pq = html.find("mlkem768x25519-sha256").unwrap();
        let classical = html.find("curve25519-sha256").unwrap();
        assert!(pq < classical, "PQ algorithms come first");
        assert!(html.contains("<span class=\"pq\">PQ</span>"));
        assert!(html.contains("already negotiates post-quantum"));
    }

    #[test]
    fn an_empty_report_says_so() {
        let r = Report::new(
            ReportTarget {
                input: "a".into(),
                host: "a".into(),
                tls_port: None,
                ssh_port: None,
            },
            RequestInfo {
                protocol: ProtocolSelection::Tls,
                mode: ModeSelection::Vanilla,
            },
        );
        assert!(report_html(&r, "/x").contains("no results"));
    }
}
