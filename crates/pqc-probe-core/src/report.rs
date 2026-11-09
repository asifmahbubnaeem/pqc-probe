//! The public JSON report. **This is a contract**: the CLI's `--output json`, the web API and
//! anything built on top (the planned Migration Dashboard) all read exactly this shape.
//!
//! Rules (see `docs/json-schema.md`):
//! - Every key is always present; `null` means "not applicable / not run / failed" (a failed side
//!   says why in `errors`).
//! - Adding a field is a compatible change. Removing, renaming, retyping or changing the meaning of
//!   a field bumps [`SCHEMA_VERSION`] and ships a migration note.
//! - Consumers must ignore unknown fields and tolerate new string values in documented enums.
//! - `schema/report-v1.json` is generated from these types; a test fails if they drift apart.
//!
//! These types deliberately sit between the probe internals and the wire format, so the internals
//! can change without silently changing what consumers see.

use crate::ssh::{DualSshReport, SshKexDiff, SshReport};
use crate::{DualProbeReport, KemDiff, ProbeReport, TlsReport};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

/// Major version of the report schema. Bumped only for incompatible changes.
pub const SCHEMA_VERSION: u32 = 1;

/// One probe run against one target.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct Report {
    /// Major version of this schema (currently 1).
    pub schema_version: u32,
    /// The program that produced the report.
    pub tool: ToolInfo,
    /// When the report was produced: UTC, RFC 3339, e.g. "2026-11-09T14:20:00Z".
    pub generated_at: String,
    pub target: ReportTarget,
    /// What was asked for.
    pub request: RequestInfo,
    /// TLS results; null when TLS was not requested.
    pub tls: Option<TlsSection>,
    /// SSH results; null when SSH was not requested.
    pub ssh: Option<SshSection>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ToolInfo {
    pub name: String,
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ReportTarget {
    /// The target exactly as the user gave it.
    pub input: String,
    pub host: String,
    /// TLS port probed; null when TLS was not requested.
    pub tls_port: Option<u16>,
    /// SSH port probed; null when SSH was not requested.
    pub ssh_port: Option<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct RequestInfo {
    pub protocol: ProtocolSelection,
    pub mode: ModeSelection,
}

/// Which protocol(s) were requested.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum ProtocolSelection {
    Tls,
    Ssh,
    Both,
}

/// Which client stack(s) were requested: the stock one, the experimental PQ one, or both (diffed).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum ModeSelection {
    Vanilla,
    Experimental,
    Both,
}

/// Why a side produced no result, when it didn't.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct SideErrors {
    pub vanilla: Option<String>,
    pub experimental: Option<String>,
}

/// TLS results per client stack.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct TlsSection {
    /// Result with the stock client; null if not requested or failed (see `errors`).
    pub vanilla: Option<TlsReport>,
    /// Result with the experimental PQ client; null if not requested or failed.
    pub experimental: Option<TlsReport>,
    /// Difference between the two; null unless both sides produced a result.
    pub diff: Option<KemDiff>,
    pub errors: SideErrors,
}

/// SSH results per client.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SshSection {
    /// Result with the stock ssh client; null if not requested or failed (see `errors`).
    pub vanilla: Option<SshClientResult>,
    /// Result with the experimental PQ client; null if not requested or failed.
    pub experimental: Option<SshClientResult>,
    /// Difference between the two; null unless both sides produced a result.
    pub diff: Option<SshKexDiff>,
    pub errors: SideErrors,
}

/// What one ssh client saw.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SshClientResult {
    /// First line of this client's `ssh -V`.
    pub client_version: Option<String>,
    /// The server's software version string (some servers, e.g. GitHub, randomize it).
    pub server_version: Option<String>,
    /// Every KEX algorithm the server offered, including protocol markers such as `kex-strict-*`.
    pub server_offered_kex: Vec<String>,
    /// The subset of the server's offer that this client negotiated successfully.
    pub client_can_negotiate: Vec<String>,
}

impl From<SshReport> for SshClientResult {
    fn from(r: SshReport) -> Self {
        Self {
            client_version: r.client_version,
            server_version: r.server_version,
            server_offered_kex: r.server_offered_kex,
            client_can_negotiate: r.client_can_negotiate,
        }
    }
}

impl TlsSection {
    /// A single-stack run: `is_experimental` says which side the result belongs to.
    pub fn from_single(is_experimental: bool, report: ProbeReport) -> Self {
        let result = report.tls;
        let (vanilla, experimental) = if is_experimental {
            (None, result)
        } else {
            (result, None)
        };
        Self {
            vanilla,
            experimental,
            diff: None,
            errors: SideErrors::default(),
        }
    }

    pub fn from_dual(d: DualProbeReport) -> Self {
        let both = d.vanilla.is_some() && d.experimental.is_some();
        Self {
            vanilla: d.vanilla.and_then(|r| r.tls),
            experimental: d.experimental.and_then(|r| r.tls),
            diff: both.then_some(d.diff),
            errors: SideErrors {
                vanilla: d.vanilla_error,
                experimental: d.experimental_error,
            },
        }
    }
}

impl SshSection {
    pub fn from_single(is_experimental: bool, report: SshReport) -> Self {
        let result = Some(SshClientResult::from(report));
        let (vanilla, experimental) = if is_experimental {
            (None, result)
        } else {
            (result, None)
        };
        Self {
            vanilla,
            experimental,
            diff: None,
            errors: SideErrors::default(),
        }
    }

    pub fn from_dual(d: DualSshReport) -> Self {
        let both = d.vanilla.is_some() && d.experimental.is_some();
        Self {
            vanilla: d.vanilla.map(SshClientResult::from),
            experimental: d.experimental.map(SshClientResult::from),
            diff: both.then_some(d.diff),
            errors: SideErrors {
                vanilla: d.vanilla_error,
                experimental: d.experimental_error,
            },
        }
    }
}

impl Report {
    /// Start a report for `target`/`request`, stamped with the current time and tool version.
    pub fn new(target: ReportTarget, request: RequestInfo) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            tool: ToolInfo {
                name: "pqc-probe".to_string(),
                version: env!("CARGO_PKG_VERSION").to_string(),
            },
            generated_at: now_rfc3339(),
            target,
            request,
            tls: None,
            ssh: None,
        }
    }

    pub fn with_tls(mut self, tls: Option<TlsSection>) -> Self {
        self.tls = tls;
        self
    }

    pub fn with_ssh(mut self, ssh: Option<SshSection>) -> Self {
        self.ssh = ssh;
        self
    }
}

/// The JSON Schema for [`Report`], pretty-printed with a trailing newline.
/// This is what is committed as `schema/report-v1.json`.
pub fn schema_json() -> String {
    let schema = schemars::schema_for!(Report);
    let mut value = serde_json::to_value(&schema).expect("schema serializes");
    require_all_properties(&mut value);
    let mut s = serde_json::to_string_pretty(&value).expect("schema serializes");
    s.push('\n');
    s
}

/// Every key we emit is always serialized (absent data is `null`, never omitted), so the schema
/// lists every property as `required`. schemars would otherwise leave `Option` and
/// `#[serde(default)]` fields out of `required`. Nullability is untouched.
fn require_all_properties(node: &mut serde_json::Value) {
    match node {
        serde_json::Value::Object(map) => {
            if let Some(serde_json::Value::Object(props)) = map.get("properties") {
                let mut names: Vec<String> = props.keys().cloned().collect();
                names.sort();
                map.insert("required".into(), serde_json::json!(names));
            }
            for v in map.values_mut() {
                require_all_properties(v);
            }
        }
        serde_json::Value::Array(items) => items.iter_mut().for_each(require_all_properties),
        _ => {}
    }
}

/// Format Unix seconds as an RFC 3339 UTC timestamp ("2026-11-09T14:20:00Z").
/// Civil-from-days after Howard Hinnant's date algorithms; avoids a time-crate dependency.
pub fn rfc3339_utc(unix_secs: u64) -> String {
    let days = (unix_secs / 86_400) as i64;
    let rem = unix_secs % 86_400;
    let (h, m, s) = (rem / 3_600, (rem % 3_600) / 60, rem % 60);

    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { y + 1 } else { y };
    format!("{year:04}-{month:02}-{d:02}T{h:02}:{m:02}:{s:02}Z")
}

fn now_rfc3339() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    rfc3339_utc(secs)
}

#[cfg(test)]
mod report_tests {
    use super::*;
    use crate::{CertInfo, KemResult, Target};

    #[test]
    fn rfc3339_known_values() {
        assert_eq!(rfc3339_utc(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339_utc(86_399), "1970-01-01T23:59:59Z");
        assert_eq!(rfc3339_utc(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(rfc3339_utc(1_700_000_000), "2023-11-14T22:13:20Z");
        assert_eq!(rfc3339_utc(1_709_164_800), "2024-02-29T00:00:00Z");
        assert_eq!(rfc3339_utc(4_102_444_800), "2100-01-01T00:00:00Z");
    }

    fn tls_fixture() -> TlsReport {
        TlsReport {
            protocol_version: Some("TLSv1.3".into()),
            cipher: Some("TLS_AES_256_GCM_SHA384".into()),
            kems_tried: vec![KemResult {
                offered: "X25519MLKEM768".into(),
                negotiated: Some("X25519MLKEM768".into()),
                handshake_succeeded: true,
            }],
            cert_sig_alg: Some("ecdsa-with-SHA256".into()),
            peer_sig_alg: Some("ECDSA".into()),
            cert_chain: vec![CertInfo {
                depth: 0,
                subject: "CN=example.com".into(),
                issuer: "CN=Example CA".into(),
                signature_algorithm: Some("ecdsa-with-SHA256".into()),
                public_key_type: Some("EC".into()),
                public_key_bits: None,
                not_before: None,
                not_after: None,
                self_signed: false,
                post_quantum: false,
            }],
            openssl_version: Some("OpenSSL 3.5.2 5 Aug 2025".into()),
        }
    }

    fn request() -> RequestInfo {
        RequestInfo {
            protocol: ProtocolSelection::Both,
            mode: ModeSelection::Both,
        }
    }

    fn target() -> ReportTarget {
        ReportTarget {
            input: "example.com:443".into(),
            host: "example.com".into(),
            tls_port: Some(443),
            ssh_port: None,
        }
    }

    #[test]
    fn json_shape_is_stable_and_keys_are_always_present() {
        let probe = ProbeReport {
            target: Target::new("example.com", 443),
            tls: Some(tls_fixture()),
        };
        let report =
            Report::new(target(), request()).with_tls(Some(TlsSection::from_single(false, probe)));
        let v = serde_json::to_value(&report).unwrap();

        assert_eq!(v["schema_version"], 1);
        assert_eq!(v["tool"]["name"], "pqc-probe");
        assert_eq!(v["request"]["protocol"], "both");
        assert_eq!(v["request"]["mode"], "both");
        assert_eq!(v["target"]["host"], "example.com");
        assert_eq!(v["target"]["tls_port"], 443);
        assert!(v["target"]["ssh_port"].is_null());
        assert_eq!(v["tls"]["vanilla"]["cipher"], "TLS_AES_256_GCM_SHA384");
        assert_eq!(
            v["tls"]["vanilla"]["kems_tried"][0]["offered"],
            "X25519MLKEM768"
        );
        assert_eq!(
            v["tls"]["vanilla"]["cert_chain"][0]["subject"],
            "CN=example.com"
        );
        // keys present even when empty
        assert!(v["tls"]["experimental"].is_null());
        assert!(v["tls"]["diff"].is_null());
        assert!(v["tls"]["errors"]["vanilla"].is_null());
        assert!(v.get("ssh").is_some() && v["ssh"].is_null());
        assert!(v["generated_at"].as_str().unwrap().ends_with('Z'));
    }

    #[test]
    fn json_round_trips() {
        let report = Report::new(target(), request());
        let text = serde_json::to_string(&report).unwrap();
        let back: Report = serde_json::from_str(&text).unwrap();
        assert_eq!(
            serde_json::to_value(&report).unwrap(),
            serde_json::to_value(&back).unwrap()
        );
    }

    #[test]
    fn dual_with_a_failed_side_has_no_diff_and_says_why() {
        let dual = DualProbeReport {
            target: Target::new("example.com", 443),
            vanilla: Some(ProbeReport {
                target: Target::new("example.com", 443),
                tls: Some(tls_fixture()),
            }),
            experimental: None,
            diff: KemDiff::default(),
            vanilla_error: None,
            experimental_error: Some("probe timed out".into()),
        };
        let s = TlsSection::from_dual(dual);
        assert!(s.vanilla.is_some());
        assert!(s.experimental.is_none());
        assert!(s.diff.is_none());
        assert_eq!(s.errors.experimental.as_deref(), Some("probe timed out"));
    }

    #[test]
    fn ssh_dual_keeps_diff_when_both_sides_succeed() {
        let side = |version: &str| SshReport {
            target: Target::new("example.com", 22),
            server_version: Some("OpenSSH_9.6".into()),
            server_offered_kex: vec!["curve25519-sha256".into()],
            client_can_negotiate: vec!["curve25519-sha256".into()],
            client_version: Some(version.into()),
        };
        let dual = DualSshReport {
            target: Target::new("example.com", 22),
            vanilla: Some(side("OpenSSH_9.6p1")),
            experimental: Some(side("OpenSSH_10.4")),
            diff: SshKexDiff::default(),
            vanilla_error: None,
            experimental_error: None,
        };
        let s = SshSection::from_dual(dual);
        assert!(s.diff.is_some());
        assert_eq!(
            s.experimental.unwrap().client_version.as_deref(),
            Some("OpenSSH_10.4")
        );
    }

    /// The docs promise every key is always present, so the schema must say `required`.
    #[test]
    fn schema_requires_every_documented_key() {
        let v: serde_json::Value = serde_json::from_str(&schema_json()).unwrap();
        let required = |node: &serde_json::Value| -> Vec<String> {
            node["required"]
                .as_array()
                .unwrap_or_else(|| panic!("no `required` list on {node}"))
                .iter()
                .map(|x| x.as_str().unwrap().to_string())
                .collect()
        };
        let has = |list: &[String], keys: &[&str]| {
            for k in keys {
                assert!(list.iter().any(|x| x == k), "`{k}` missing from {list:?}");
            }
        };
        has(
            &required(&v),
            &[
                "schema_version",
                "tool",
                "generated_at",
                "target",
                "request",
                "tls",
                "ssh",
            ],
        );
        let defs = &v["$defs"];
        has(&required(&defs["ReportTarget"]), &["tls_port", "ssh_port"]);
        for section in ["TlsSection", "SshSection"] {
            has(
                &required(&defs[section]),
                &["vanilla", "experimental", "diff", "errors"],
            );
        }
        has(&required(&defs["SideErrors"]), &["vanilla", "experimental"]);
        has(
            &required(&defs["TlsReport"]),
            &[
                "kems_tried",
                "cert_chain",
                "openssl_version",
                "cipher",
                "protocol_version",
            ],
        );
        has(&required(&defs["SshKexDiff"]), &["mainline_since"]);
        has(
            &required(&defs["SshClientResult"]),
            &["client_version", "server_version"],
        );
    }

    /// The committed schema must match what the types generate. After an intentional,
    /// compatible change, regenerate with:
    ///   UPDATE_SCHEMA=1 cargo test -p pqc-probe-core committed_schema_matches_types
    #[test]
    fn committed_schema_matches_types() {
        let generated = schema_json();
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../schema/report-v1.json");
        if std::env::var_os("UPDATE_SCHEMA").is_some() {
            std::fs::write(path, &generated).expect("write schema/report-v1.json");
            return;
        }
        let committed = std::fs::read_to_string(path).unwrap_or_else(|_| {
            panic!(
                "schema/report-v1.json is missing. Generate it with: \
                 UPDATE_SCHEMA=1 cargo test -p pqc-probe-core committed_schema_matches_types"
            )
        });
        assert!(
            committed == generated,
            "schema/report-v1.json is out of date with the report types. If the change is \
             compatible, regenerate: UPDATE_SCHEMA=1 cargo test -p pqc-probe-core \
             committed_schema_matches_types. If it is breaking, bump SCHEMA_VERSION and add \
             schema/report-v2.json instead."
        );
    }
}
