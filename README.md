# pqc-probe

> Detect post-quantum crypto on TLS and SSH endpoints, in both vanilla and experimental stacks.

**Project 1 of the PQC trilogy. See also [pqc-bench](https://github.com/asifmahbubnaeem/pqc-bench) (Project 3, complete) and [pqc-migration-dashboard](https://github.com/asifmahbubnaeem/pqc-migration-dashboard) (Project 2, planned).**

## What it does

Given a target (`host:port`), reports which post-quantum algorithms the server supports:

- TLS 1.3 KEMs (ML-KEM-768 hybrid, X25519MLKEM768, classical fallbacks)
- Signature algorithm on the server's cert
- Signature algorithm used in CertificateVerify
- (Weeks 2+) SSH KEX algorithms (ML-KEM, Kyber, hybrid, classical)

Two probe modes:

- `--mode vanilla` — uses stock OpenSSL 3.5.x. What a production TLS client actually sees today.
- `--mode experimental` — uses OpenSSL + oqs-provider. Catches the extended codepoint set your staging environment might advertise.

The diff between the two modes is actionable: it tells you what's deployable today vs what's advertisement-only.

## Current status

**Week 1 of ~12.** Working TLS probe via vanilla OpenSSL, CLI only.

Deliverables planned for v1.0:
1. `pqc-probe-cli` — CLI binary (Weeks 1-4)
2. `pqc-probe-web` — hosted web UI (Weeks 5-6)
3. GitHub Action — scan-your-endpoints workflow (Weeks 7-8)
4. Docker image bundling CLI + openssl + oqs-provider (Weeks 7-8)

## Quick start (Week 1)

Requires: Rust ≥ 1.75, OpenSSL ≥ 3.5.0 on `$PATH`.

```bash
cd pqc-probe
cargo build --release
./target/release/pqc-probe probe google.com:443
```

Expected output (approximately):

```
Target: google.com:443

TLS:
  Protocol:          TLSv1.3
  Cipher:            TLS_AES_256_GCM_SHA384
  Cert sig alg:      ecdsa-with-SHA256
  Peer sig alg:      ECDSA

  KEMs:
    offered                   negotiated                handshake
    X25519                    X25519                    ok
    P-256                     P-256                     ok
    X25519MLKEM768            X25519MLKEM768            ok
    SecP256r1MLKEM768         -                         fail
```

JSON output: `pqc-probe probe google.com:443 --output json`.

Override the openssl binary: `PQC_PROBE_OPENSSL=/opt/openssl-3.5/bin/openssl pqc-probe probe ...`.

## Architecture

```
pqc-probe/
├── crates/
│   ├── pqc-probe-core/     core probe logic + types, no CLI concerns
│   ├── pqc-probe-cli/      binary wrapping core
│   └── pqc-probe-web/      (Weeks 5-6) axum server
└── action/                 (Weeks 7-8) GitHub Action
```

`pqc-probe-core` returns a `ProbeReport` structure consumable from any of the three frontends. All three share one implementation.

## Why Rust

Three reasons:
1. Single static binary — easy to distribute and run in air-gapped environments (common for the kind of security team that runs PQ audits).
2. Strong type system makes dual-mode probing (vanilla vs experimental) cleanly expressible via enums + match exhaustiveness.
3. `rustls` + `aws-lc-rs` are PQ-aware and future-proof; the probe can migrate from shell-outs to native TLS in v2.

## License

Dual-licensed MIT OR Apache-2.0 at the user's option. Commercial / enterprise support available — contact [asifnaim0123@gmail.com](mailto:asifnaim0123@gmail.com).

## Roadmap

| Week | Deliverable |
|---|---|
| 1 | Core crate + CLI with vanilla TLS probing (this release) |
| 2 | Experimental mode (oqs-provider), dual-stack diff output |
| 3 | SSH probing (via `ssh -v` parsing or native rust-ssh) |
| 4 | Output formats polish, cert chain analysis |
| 5-6 | Web UI (axum) with form + JSON API |
| 7-8 | GitHub Action + Docker image |
| 9-10 | Blog series + release |
| 11-12 | Hardening based on first-wave user feedback |
