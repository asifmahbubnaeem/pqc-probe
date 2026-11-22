# pqc-probe

> Which post-quantum key exchanges does a server actually support, over TLS and SSH?

[![ci](https://github.com/asifmahbubnaeem/pqc-probe/actions/workflows/ci.yml/badge.svg)](https://github.com/asifmahbubnaeem/pqc-probe/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)](#license)

**Project 1 of the PQC trilogy. See also [pqc-bench](https://github.com/asifmahbubnaeem/pqc-bench) (Project 3, complete) and [pqc-migration-dashboard](https://github.com/asifmahbubnaeem/pqc-migration-dashboard) (Project 2, planned).**

pqc-probe connects to a server, tries each key exchange one at a time, and reports which ones
complete a real handshake. It does this with two client stacks side by side: the stock
OpenSSL and OpenSSH a production client uses today, and experimental builds with the Open
Quantum Safe algorithms. The difference between the two shows what is deployable now and what
only works with experimental clients.

It ships as a command-line tool, a web service, a Docker image and a GitHub Action, all built
on one Rust library and one public JSON report format.

## What it reports

- **TLS 1.3 key exchange groups**: classical (X25519, P-256, P-384, P-521) and ML-KEM hybrids
  (X25519MLKEM768, SecP256r1MLKEM768, SecP384r1MLKEM1024). Each group is offered alone, so the
  report shows what the server *supports*, not just what it prefers.
- **SSH key exchange**: the server's full offer, read straight from its key exchange packet,
  and a real, paced key exchange for each post-quantum algorithm both sides support
  (ML-KEM, sntrup761, and the OQS algorithms).
- **Certificates**: the chain as sent, with signature and key algorithms flagged classical or
  post-quantum, and the algorithm the server signed the handshake with.
- **A diff** between the stock and experimental clients, and a note when the stock client is
  itself post-quantum capable (OpenSSL 3.5+), which makes a TLS diff say little about the server.

## Example

```text
$ docker run --rm --init ghcr.io/asifmahbubnaeem/pqc-probe:edge \
    pqc-probe probe github.com --protocol both --mode both

TLS KEMs (vanilla  vs  experimental):
  offered                   vanilla           experimental
  X25519                    ok                ok
  P-256                     ok                ok
  P-384                     -                 -
  P-521                     -                 -
  X25519MLKEM768            -                 -
  SecP256r1MLKEM768         -                 -
  SecP384r1MLKEM1024        -                 -

SSH KEX (server offer × client support):
  server offers                         mainline ssh      OQS-OpenSSH
  mlkem768x25519-sha256                 ok (tested)       ok (tested)
  sntrup761x25519-sha512                ok (tested)       ok (tested)
  sntrup761x25519-sha512@openssh.com    ok (tested)       ok (tested)
  curve25519-sha256                     ok                ok
  ...
```

(Trimmed.) GitHub's SSH service completes post-quantum key exchanges; its TLS front end, at the
time of this run, did not accept ML-KEM even though the stock client offered it.

## Install

| Way | Gets you | Needs |
|---|---|---|
| **Docker** | CLI, web service, both client stacks ready | Docker |
| `cargo install pqc-probe` | the CLI | Rust 1.89+, OpenSSL 3.5 and OpenSSH on `PATH` |
| From source | everything | as above |

**Docker** is the easiest way to get the experimental stacks, which otherwise have to be built
by hand:

```bash
docker run --rm --init ghcr.io/asifmahbubnaeem/pqc-probe:edge pqc-probe probe example.com
```

See [docs/docker.md](docs/docker.md) for what is inside and how to run it hardened.

**From crates.io or source**, stock mode works with the system's OpenSSL 3.5 and OpenSSH. For
the experimental mode, build oqs-provider and OQS-OpenSSH as described in
[docs/oqs-setup.md](docs/oqs-setup.md) and [docs/ssh-setup.md](docs/ssh-setup.md), then point
pqc-probe at them:

```bash
export PQC_PROBE_OPENSSL=/opt/openssl-3.5/bin/openssl          # stock TLS client (default: openssl)
export PQC_PROBE_OPENSSL_OQS=/opt/openssl-3.5/bin/openssl-oqs  # experimental TLS client
export PQC_PROBE_SSH=/usr/bin/ssh                              # stock SSH client (default: ssh)
export PQC_PROBE_SSH_OQS=/opt/oqs-openssh/bin/ssh              # experimental SSH client
```

## Usage

```bash
pqc-probe probe example.com                                  # TLS, stock client
pqc-probe probe example.com --protocol both --mode both      # TLS and SSH, both stacks, diff
pqc-probe probe git.example.com --protocol ssh --ssh-port 2222
pqc-probe probe example.com --protocol both --output json    # machine-readable report
pqc-probe scan tranco-top1000.csv --output results.csv       # batch survey (CSV: rank,domain)
```

| Option | Default | Meaning |
|---|---|---|
| `--protocol` | `tls` | `tls`, `ssh` or `both` |
| `--mode` | `vanilla` | `vanilla` (stock clients), `experimental` (OQS clients) or `both` (with a diff) |
| `--output` | `human` | `human` or `json` |
| `--tls-port` / `--ssh-port` | 443 / 22 | override the port (a port in the target is used for TLS) |
| `--timeout` | 10 | seconds per connection attempt |
| `--ssh-verify` | 8 | how many post-quantum SSH algorithms get a real handshake test (0 = none) |

Reading the SSH table: **ok (tested)** means a key exchange with this server completed;
**ok** means the client implements it but it was not tried (only post-quantum algorithms are
tried, to stay polite); **fails** means the exchange definitely failed; **?** means the test
could not tell (timeout, dropped connection), and such rows are left out of the diff.

## Web service, GitHub Action, JSON

- **Web service** (`pqc-probe-web`): a JSON API and an HTML page, built for hosting: target
  policy against internal networks, per-client and per-target limits, job queue.
  See [docs/web.md](docs/web.md) and the [threat model](docs/threat-model.md).
- **GitHub Action**: probe your hosts from a workflow, keep the reports, optionally fail on a
  policy:

  ```yaml
  - uses: asifmahbubnaeem/pqc-probe@v0.2.0
    with:
      targets: api.example.com, git.example.com:2222
      require-pq-ssh: "true"
  ```

  See [docs/github-action.md](docs/github-action.md).
- **JSON reports** follow [schema/report-v1.json](schema/report-v1.json), a public contract:
  fields are only ever added within a schema version. See [docs/json-schema.md](docs/json-schema.md).

## Findings

A survey of the Tranco top 1000 on 2026-11-06, from one vantage point, IPv4 only: of the 695
domains that completed a TLS handshake, **504 (72.5%) accept X25519MLKEM768**. The other 305
failed for reasons unrelated to post-quantum support (197 had no DNS answer, 54 offer only
TLS 1.2 or older, 39 do not listen on 443). Data, method and charts: [results/](results/).

## How it works

- Probes drive real clients (`openssl s_client`, `ssh`) rather than reimplementing the
  handshakes, so the answer is what those clients actually get. Everything forces IPv4.
- The SSH offer is read from the server's unencrypted key exchange packet instead of from
  `ssh -vv` logs, because OpenSSH cuts debug lines at about 1 KB and long offers were truncated.
- SSH handshake tests are sequential and paced at about one per second: OpenSSH 9.8+ penalises
  sources that open many short connections (`PerSourcePenalties`), which otherwise turns real
  support into false negatives.
- The hosted service resolves each target once, checks every address against private and
  special ranges, and connects to the checked address, so DNS rebinding cannot redirect it.

## Limitations

- IPv4 only.
- Results describe what a handshake showed from one place at one time; a server behind a load
  balancer can answer differently per connection.
- SSH host key (signature) algorithms are not reported yet, only key exchange.
- The experimental stacks are as good as the OQS builds behind them; their versions are recorded
  in the Docker image's `/opt/pqc-probe/VERSIONS`.

## Building and contributing

```bash
cargo build --release
scripts/check.sh          # fmt, clippy, tests, release build
scripts/check.sh smoke    # plus a few live probes
```

```
crates/
  pqc-probe-core/   probe logic, policy, report types (library)
  pqc-probe-cli/    the pqc-probe command (package name: pqc-probe)
  pqc-probe-web/    web service
action/             GitHub Action
docker/, Dockerfile image
schema/             JSON Schema of the report
```

Changes are listed in [CHANGELOG.md](CHANGELOG.md).

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option.
Commercial / enterprise support available: contact
[asifnaim0123@gmail.com](mailto:asifnaim0123@gmail.com).
