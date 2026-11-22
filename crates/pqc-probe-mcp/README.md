# pqc-probe-mcp

An [MCP](https://modelcontextprotocol.io) server that lets AI agents check whether a server
supports post-quantum cryptography over TLS and SSH. It runs the same probe code as the
`pqc-probe` CLI and web service.

## Tools

| Tool | What it does | Network |
| --- | --- | --- |
| `probe_tls` | Which TLS key-exchange groups the host negotiates (e.g. `X25519MLKEM768`), and its certificate's signature algorithm | Real TLS handshakes to the host |
| `probe_ssh` | Which SSH key exchanges the host offers (e.g. `mlkem768x25519-sha256`) and which a client completes | Real SSH connections; never logs in |
| `probe_limits` | Allowed ports, private-address blocking, probe budget, installed client stacks | None |

Each probe result starts with a few plain lines and a verdict, then the full JSON report
([schema v1](../../schema/report-v1.json)):

```
TLS example.com:443: post-quantum key exchange supported: YES
- stock client: post-quantum groups negotiated: X25519MLKEM768; certificate signature ecdsa-with-SHA256 (classical)
Full JSON report (schema v1) follows.
```

The verdict is `UNKNOWN` when no handshake completed at all (closed or filtered port, not a TLS
service). A closed port is never reported as "no post-quantum support".

## Guardrails

An agent is a fast loop that may be reading text written by someone else (a web page, an
issue, a log). So by default the server applies the hosted web service's rules:

- **No private or internal targets.** Loopback, RFC 1918, link-local and cloud metadata
  (169.254.169.254), CGNAT and other reserved ranges are refused, including tricky spellings
  such as `2130706433` or `0x7f.0.0.1`. The name is resolved once and the probe connects to
  that checked address, so DNS rebinding can't swap it.
- **Port allowlist:** 22, 443, 465, 636, 853, 993, 995, 2222, 8443 (`--allowed-ports`).
- **Probe budget:** one probe at a time, at most 10 started per minute
  (`--probes-per-minute`). A refused target doesn't spend the budget.
- **Deadline** of 90 s per tool call (`--call-timeout-secs`), under most clients' own timeouts.

Refusals come back as tool errors (`isError: true`) with a plain sentence, so the model can tell
the user why instead of retrying.

`--unrestricted-targets` turns the policy off so you can probe your own test bench on private
addresses. Use it only with an agent that reads nothing you don't control.

## Build

```sh
cargo build --release -p pqc-probe-mcp
```

The probes shell out to `openssl` (3.5 or newer for ML-KEM) and `ssh`, like the CLI. Pass
`--openssl-oqs` and `--ssh-oqs` to enable the experimental client stacks
(see [docs/oqs-setup.md](../../docs/oqs-setup.md)).

## Connect a client

Claude Code:

```sh
claude mcp add pqc-probe -- /path/to/pqc-probe-mcp
```

Claude Desktop and most other clients take a JSON entry like this:

```json
{
  "mcpServers": {
    "pqc-probe": {
      "command": "/path/to/pqc-probe-mcp",
      "args": ["--probes-per-minute", "5"]
    }
  }
}
```

Logs go to stderr; stdout carries the protocol.

## A local agent, no framework

[`examples/agent_loop.py`](examples/agent_loop.py) is an agent loop in plain Python (standard
library only): it starts this server, hands its tools to a local Ollama model, runs the
call-tool-reply loop and writes every step to a JSONL trace.

```sh
python3 crates/pqc-probe-mcp/examples/agent_loop.py \
  --server ./target/release/pqc-probe-mcp \
  "Does cloudflare.com support post-quantum key exchange over TLS?"
```

Options: `--model` (default `qwen3:8b`), `--max-steps`, `--think`, `--trace`,
`--server-arg` (repeatable, passed to the server), and `--summary-only`, which sends the model
only each result's verdict lines instead of the full JSON report. That keeps the prompt small,
which matters for a local model on a CPU.
