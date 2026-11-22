//! The MCP tools.
//!
//! Three tools: `probe_tls`, `probe_ssh` and `probe_limits`. The probes run through the same
//! code as the hosted web service (`pqc_probe_web::prober`), and by default through the same
//! target policy: no private or internal addresses, a port allowlist, one DNS lookup pinned
//! for the connection. An agent is a stranger with a fast loop, so it gets the hosted rules.
//!
//! Failures the agent should read and act on (refused target, budget used up, probe failed)
//! come back as tool errors (`is_error: true`) with a plain sentence, not as protocol errors:
//! MCP clients usually hide protocol-error text from the model.

use crate::limit::Limiter;
use crate::summary::summarize;
use crate::target::split_host;
use pqc_probe_core::policy::{prepare_target, validate_host, Policy, PolicyError};
use pqc_probe_core::{ModeSelection, ProtocolSelection, Target};
use pqc_probe_web::model::ProbeRequest;
use pqc_probe_web::prober::{CliProber, ProbeJob, Prober};
use rmcp::handler::server::{router::tool::ToolRouter, wrapper::Parameters};
use rmcp::model::{CallToolResult, ContentBlock, Implementation, ServerCapabilities, ServerConfig};
use rmcp::{schemars, tool, tool_handler, tool_router, ErrorData as McpError, ServerHandler};
use serde::Deserialize;
use std::sync::Arc;
use std::time::Duration;

/// Settings fixed at start-up.
pub struct Settings {
    pub policy: Policy,
    /// Skip the hosted policy (private addresses and any port allowed). For your own test bench
    /// only; never for an agent that reads untrusted text.
    pub unrestricted: bool,
    pub has_experimental_tls: bool,
    pub has_experimental_ssh: bool,
    /// Whole-call deadline. MCP clients time out tool calls too; stay under theirs.
    pub call_timeout: Duration,
}

#[derive(Clone)]
pub struct ProbeServer {
    prober: Arc<CliProber>,
    limiter: Arc<Limiter>,
    settings: Arc<Settings>,
    tool_router: ToolRouter<Self>,
}

/// Which client stack(s) to probe with.
#[derive(Debug, Clone, Copy, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// The stock client: what an ordinary up-to-date client sees today.
    Vanilla,
    /// Only the experimental post-quantum client (OQS).
    Experimental,
    /// Both clients, plus a diff of what only the experimental one gets.
    Both,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct TlsArgs {
    /// Host name or IPv4 address, e.g. "example.com". A URL or "host:port" is accepted too.
    pub host: String,
    /// TLS port. Defaults to 443, or the port written in `host`.
    #[serde(default)]
    pub port: Option<u16>,
    /// Client stack(s) to use. Leave it out unless asked: the server picks "both" when the
    /// experimental client is installed, else "vanilla".
    #[serde(default)]
    pub mode: Option<Mode>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SshArgs {
    /// Host name or IPv4 address, e.g. "github.com". "user@host" or "host:port" is accepted too.
    pub host: String,
    /// SSH port. Defaults to 22, or the port written in `host`.
    #[serde(default)]
    pub port: Option<u16>,
    /// Client stack(s) to use. Leave it out unless asked: the server picks "both" when the
    /// experimental client is installed, else "vanilla".
    #[serde(default)]
    pub mode: Option<Mode>,
}

/// Appended to every failed probe. A small model reads "timed out" on a host with no SSH
/// service and concludes "not post-quantum ready"; the absence of a measurement is not a "no".
const NOTHING_MEASURED: &str = "Verdict: UNKNOWN. Nothing was measured: the service may not exist on this port, or it may be filtered. This is not evidence for or against post-quantum support.";

fn tool_error(msg: impl Into<String>) -> CallToolResult {
    CallToolResult::error(vec![ContentBlock::text(msg.into())])
}

impl ProbeServer {
    pub fn new(prober: CliProber, limiter: Limiter, settings: Settings) -> Self {
        Self {
            prober: Arc::new(prober),
            limiter: Arc::new(limiter),
            settings: Arc::new(settings),
            tool_router: Self::tool_router(),
        }
    }

    /// The mode to run, plus a note when the request was adjusted.
    ///
    /// Small models often pass `mode` even when told not to. If the experimental client isn't
    /// installed, the question ("does this host support PQ?") can still be answered with the
    /// stock client, so run that and say so, rather than refuse and hope the model retries.
    fn resolve_mode(
        &self,
        asked: Option<Mode>,
        has_experimental: bool,
    ) -> (ModeSelection, Option<String>) {
        let wanted = match asked {
            None if has_experimental => ModeSelection::Both,
            None => ModeSelection::Vanilla,
            Some(Mode::Vanilla) => ModeSelection::Vanilla,
            Some(Mode::Experimental) => ModeSelection::Experimental,
            Some(Mode::Both) => ModeSelection::Both,
        };
        if wanted != ModeSelection::Vanilla && !has_experimental {
            return (
                ModeSelection::Vanilla,
                Some(
                    "note: the experimental client is not installed here, so only the stock client was used"
                        .to_string(),
                ),
            );
        }
        (wanted, None)
    }

    /// Validate, apply the policy and pin the address. Errors are sentences for the agent.
    async fn prepare(&self, host: &str, port: u16) -> Result<Target, String> {
        if self.settings.unrestricted {
            validate_host(host).map_err(|e| e.to_string())?;
            return Ok(Target::new(host, port));
        }
        prepare_target(host, port, &self.settings.policy)
            .await
            .map_err(|e| match e {
                // A blocked address is a decision, not a typo: say so, so the agent doesn't try
                // the same place under another name (a decimal IP, a DNS alias).
                PolicyError::BlockedAddress { .. } => format!(
                    "refused by policy: {e}. This server never probes private or internal addresses; tell the user instead of retrying."
                ),
                _ => format!("refused: {e}"),
            })
    }

    async fn run(
        &self,
        raw_host: &str,
        port: Option<u16>,
        default_port: u16,
        protocol: ProtocolSelection,
        (mode, note): (ModeSelection, Option<String>),
    ) -> CallToolResult {
        let (host, port_in_host) = split_host(raw_host);
        let port = port.or(port_in_host).unwrap_or(default_port);

        let target = match self.prepare(&host, port).await {
            Ok(t) => t,
            Err(e) => return tool_error(e),
        };
        let _slot = match self.limiter.try_start() {
            Ok(p) => p,
            Err(e) => return tool_error(e),
        };

        let (tls, ssh, tls_port, ssh_port) = match protocol {
            ProtocolSelection::Ssh => (None, Some(target), None, Some(port)),
            _ => (Some(target), None, Some(port), None),
        };
        let job = ProbeJob {
            request: ProbeRequest {
                target: raw_host.trim().to_string(),
                protocol,
                mode: Some(mode),
                tls_port,
                ssh_port,
            },
            mode,
            tls,
            ssh,
        };

        tracing::info!(%host, port, ?protocol, ?mode, "probe start");
        let outcome =
            tokio::time::timeout(self.settings.call_timeout, self.prober.probe(&job)).await;
        let report = match outcome {
            Err(_) => {
                return tool_error(format!(
                    "the probe did not finish within {} s; the host may be filtering connections.\n{NOTHING_MEASURED}",
                    self.settings.call_timeout.as_secs()
                ))
            }
            Ok(Err(e)) => return tool_error(format!("the probe failed: {e}\n{NOTHING_MEASURED}")),
            Ok(Ok(r)) => r,
        };
        tracing::info!(%host, port, "probe done");

        let json = match serde_json::to_value(&report) {
            Ok(v) => v,
            Err(e) => return tool_error(format!("could not encode the report: {e}")),
        };
        let mut result = CallToolResult::structured(json);
        let mut summary = summarize(&report);
        if let Some(note) = note {
            summary = format!("{note}\n{summary}");
        }
        result.content.insert(0, ContentBlock::text(summary));
        result
    }
}

#[tool_router]
impl ProbeServer {
    #[tool(
        description = "Check whether a server supports post-quantum (PQ) key exchange over TLS, e.g. ML-KEM hybrids such as X25519MLKEM768, and which signature its certificate uses. Makes real TLS connections to the host. Returns a short plain-text answer, then the full JSON report."
    )]
    async fn probe_tls(
        &self,
        Parameters(args): Parameters<TlsArgs>,
    ) -> Result<CallToolResult, McpError> {
        let mode = self.resolve_mode(args.mode, self.settings.has_experimental_tls);
        Ok(self
            .run(&args.host, args.port, 443, ProtocolSelection::Tls, mode)
            .await)
    }

    #[tool(
        description = "Check whether an SSH server offers post-quantum key exchange (e.g. mlkem768x25519-sha256, sntrup761x25519-sha512) and whether a client can complete it. Makes real SSH connections to the host but never logs in. Returns a short plain-text answer, then the full JSON report."
    )]
    async fn probe_ssh(
        &self,
        Parameters(args): Parameters<SshArgs>,
    ) -> Result<CallToolResult, McpError> {
        let mode = self.resolve_mode(args.mode, self.settings.has_experimental_ssh);
        Ok(self
            .run(&args.host, args.port, 22, ProtocolSelection::Ssh, mode)
            .await)
    }

    #[tool(
        description = "Call this whenever the user asks what you can check: which ports, hosts or addresses are allowed, how many probes you may run, or which client stacks are installed. Answer those questions from this tool's output, never from memory. Makes no network connections."
    )]
    async fn probe_limits(&self) -> Result<CallToolResult, McpError> {
        let s = &self.settings;
        let ports = if s.unrestricted || s.policy.allowed_ports.is_empty() {
            "any".to_string()
        } else {
            s.policy
                .allowed_ports
                .iter()
                .map(u16::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        };
        let text = format!(
            "allowed ports: {ports}\nprivate and internal addresses blocked: {}\nprobes per minute: {}\nexperimental TLS client installed: {}\nexperimental SSH client installed: {}\nper-call time limit: {} s",
            !s.unrestricted,
            self.limiter.per_minute(),
            s.has_experimental_tls,
            s.has_experimental_ssh,
            s.call_timeout.as_secs(),
        );
        Ok(CallToolResult::success(vec![ContentBlock::text(text)]))
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for ProbeServer {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new(env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION")))
            .with_instructions(
            "pqc-probe checks servers you name for post-quantum cryptography support. Use probe_tls for HTTPS/TLS and probe_ssh for SSH. Each probe is real traffic to that server, so probe only hosts the user asked about, once each, and do not scan lists or address ranges. If a probe is refused by policy, tell the user why instead of retrying. For any question about what you can check (ports, hosts, limits), call probe_limits instead of answering from memory. If a probe fails or says UNKNOWN, report that nothing was measured; never turn it into a yes or a no.",
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pqc_probe_web::config::ToolPaths;

    fn server(has_experimental: bool) -> ProbeServer {
        ProbeServer::new(
            CliProber::new(ToolPaths::default(), Duration::from_secs(1)),
            Limiter::new(10, 1),
            Settings {
                policy: Policy::default(),
                unrestricted: false,
                has_experimental_tls: has_experimental,
                has_experimental_ssh: has_experimental,
                call_timeout: Duration::from_secs(5),
            },
        )
    }

    #[test]
    fn falls_back_to_vanilla_with_a_note_when_experimental_is_missing() {
        let s = server(false);
        for asked in [Some(Mode::Both), Some(Mode::Experimental)] {
            let (mode, note) = s.resolve_mode(asked, false);
            assert_eq!(mode, ModeSelection::Vanilla);
            assert!(note.unwrap().contains("only the stock client"));
        }
        assert_eq!(s.resolve_mode(None, false), (ModeSelection::Vanilla, None));
    }

    #[test]
    fn honours_the_requested_mode_when_experimental_is_installed() {
        let s = server(true);
        assert_eq!(s.resolve_mode(None, true), (ModeSelection::Both, None));
        assert_eq!(
            s.resolve_mode(Some(Mode::Experimental), true),
            (ModeSelection::Experimental, None)
        );
    }
}
