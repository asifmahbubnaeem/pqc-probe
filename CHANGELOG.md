# Changelog

All notable changes to this project are listed here. The JSON report schema
(`schema/report-v1.json`) is a public contract: within a major schema version, fields are only
added, never removed or renamed.

## [Unreleased]

### Breaking (`pqc-probe-core`)

- `PolicyError` is now `#[non_exhaustive]` and has a new variant, `ResolverBusy`. Code that
  matches on it needs a wildcard arm. The next release bumps `pqc-probe-core` to 0.2.0.

### Core

- At most 32 DNS lookups (`policy::MAX_LOOKUPS`) hold a resolver thread at once. A lookup past
  its 5 s limit keeps its slot until its thread really ends, so a slow or hostile DNS server can
  no longer pin an unbounded number of threads. When all slots are taken, lookups fail at once
  with `PolicyError::ResolverBusy`, which is not retried.

### Web service

- A full resolver is answered with `503 resolver_busy` and `Retry-After: 5`. The documented list
  of error codes now includes every code the service returns.

### Web service

- An identical request that arrives while the first is still being prepared (a double-click on
  the form, a retried API call) now waits for the first one's job instead of resolving again and
  spending the client's and the target's budget. Before, a triple-click cost two tokens and two
  DNS lookups, and the third click got `429`.

### Docker image

- OQS-OpenSSH pin moved from `6717c038a` to `4c308effc` (the `OQS-v10` head on 2026-11-21). It
  brings upstream #204, which teaches `sshkey_check_sigtype` about OQS hybrid signature
  framing. The two local GCC 14 fixes are still needed and still applied (upstream #210, #211).

### Project

- CI runs ShellCheck on every shell script (`action/run.sh`, `action/test.sh`, `scripts/check.sh`,
  `docker/openssl-oqs`); the findings it raised are fixed. The action's timeout check is now a
  plain `if`, and its tests cover the upper bound (121 is refused).

## [0.1.0] - 2026-11-18

First release.

### CLI (`pqc-probe`)

- `probe` reports which key exchange groups a server negotiates over TLS 1.3 (classical and
  ML-KEM hybrids) and which key exchange algorithms it offers and completes over SSH.
- Two client stacks side by side: `--mode vanilla` (stock OpenSSL / OpenSSH), `--mode experimental`
  (OpenSSL with oqs-provider, OQS-OpenSSH), or `--mode both` with a diff.
- SSH offer read straight from the server's KEXINIT packet, so long algorithm lists are never
  truncated; client support from `ssh -Q kex`; up to 8 paced handshake tests of post-quantum
  algorithms (`--ssh-verify`), with results marked tested, supported, failed or inconclusive.
- Certificate chain report (signature and key algorithms, post-quantum flag).
- Notes when the stock client is itself post-quantum capable (OpenSSL 3.5+), so a TLS diff says
  little about the server.
- `--output json` following `schema/report-v1.json`; `scan` for batches from a CSV.

### Web service (`pqc-probe-web`)

- JSON API (`/api/v1/probes`) and a server-rendered HTML interface with no JavaScript.
- Hosted-mode target policy: one DNS lookup (IPv4 only), every address checked against private,
  loopback, link-local, metadata and other special ranges, connection pinned to the checked
  address, port allowlist.
- Limits per client (burst, rate, in flight, per day), per server address across all clients,
  and for polling; repeat requests within a minute get the earlier job back.
- Job queue with a concurrency cap, per-job deadline, result expiry; strict CSP and security
  headers. See `docs/web.md` and `docs/threat-model.md`.

### Docker image and GitHub Action

- Image with Debian 13's OpenSSL 3.5 and OpenSSH 10.0 as the stock clients, liboqs 0.15.0 with
  oqs-provider 0.11.0, and the OQS-OpenSSH client; non-root, self-checking build, published to
  `ghcr.io/asifmahbubnaeem/pqc-probe`. See `docs/docker.md`.
- GitHub Action: probe a list of hosts, keep the JSON reports, write a job summary, optionally
  fail on `require-pq-tls` / `require-pq-ssh`. See `docs/github-action.md`.

### Requirements

- Rust 1.89 or later to build from source.
