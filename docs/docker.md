# Docker image

One image holds the CLI (`pqc-probe`), the web service (`pqc-probe-web`) and both client stacks:

| | TLS | SSH |
|---|---|---|
| stock | Debian 13's `openssl` (3.5) | Debian 13's `ssh` (OpenSSH 10.0) |
| experimental | the same `openssl` with oqs-provider (`openssl-oqs`) | OQS-OpenSSH client |

Debian 13's stock clients already negotiate `X25519MLKEM768` (TLS) and `mlkem768x25519-sha256`
(SSH). Reports from the image therefore show fewer "only with the experimental client" rows
than a machine with an older stock client: that is what an up-to-date client really gets.

## Build

```bash
docker build -t pqc-probe .
```

The first build compiles liboqs twice (once for oqs-provider, once inside OQS-OpenSSH) and the
Rust workspace; expect several minutes. The build fails on purpose if oqs-provider is not
loaded or OQS-OpenSSH lacks its post-quantum algorithms. The last build step prints
`/opt/pqc-probe/VERSIONS`.

Build arguments (defaults in brackets):

| Argument | Meaning |
|---|---|
| `LIBOQS_VERSION` [0.15.0] | liboqs release for oqs-provider |
| `OQS_PROVIDER_VERSION` [0.11.0] | oqs-provider release (upstream pairs 0.11.0 with liboqs 0.15.0) |
| `OQS_OPENSSH_BRANCH` [OQS-v10] | OQS-OpenSSH branch (OpenSSH 10.4 based) |
| `OQS_OPENSSH_COMMIT` [4c308effc...] | exact OQS-OpenSSH commit; empty means the branch head |
| `OQS_OPENSSH_LIBOQS` [main] | liboqs branch or tag OQS-OpenSSH's script builds against |
| `RUST_IMAGE` [rust:1-slim-trixie] | Rust toolchain image for the build stage |

OQS-OpenSSH has no release tags, so the Dockerfile pins a commit. Its own script builds liboqs
from `main` unless `OQS_OPENSSH_LIBOQS` names a tag; the commit used is recorded in `VERSIONS`.

The Dockerfile applies two one-line fixes to OQS-OpenSSH: a missing declaration in `ssh-oqs.c`
(include order, [#210](https://github.com/open-quantum-safe/openssh/issues/210)) and a missing
prototype in `kex.h` ([#211](https://github.com/open-quantum-safe/openssh/issues/211)). GCC 13
only warns about them; Debian 13's GCC 14 refuses to compile. Each fix is applied only while the
upstream file still needs it.
OQS-OpenSSH's liboqs is shipped in `/opt/oqs-openssh/lib` and found through a run path, so it
never mixes with the TLS stack's liboqs in `/opt/liboqs/lib`.

## Run the web service

```bash
docker run --rm --init -p 127.0.0.1:8080:8080 pqc-probe
```

Then open http://127.0.0.1:8080/. Inside the container the service listens on all interfaces
(`PQC_WEB_BIND=0.0.0.0:8080`); `-p 127.0.0.1:...` keeps it reachable only from this machine.
All `PQC_WEB_*` variables from `docs/web.md` can be passed with `-e`.

Hardened, as recommended in `docs/threat-model.md`:

```bash
docker run --rm --init -p 127.0.0.1:8080:8080 \
  --read-only --tmpfs /tmp --tmpfs /home/pqc \
  --cap-drop ALL --security-opt no-new-privileges \
  --memory 512m --pids-limit 256 \
  pqc-probe
```

`--init` reaps the `openssl` and `ssh` child processes and forwards signals. The image also sets
`STOPSIGNAL SIGINT`, which the service handles, so `docker stop` shuts it down cleanly.

The container still reaches any address its network allows. On a public host, filter egress
at the network layer as well (see the threat model).

## Run the CLI

```bash
docker run --rm pqc-probe pqc-probe probe github.com --protocol both --mode both
docker run --rm pqc-probe pqc-probe probe github.com --protocol both --mode both --output json
```

The CLI does not apply the hosted-mode target policy: inside a container it can still reach
private addresses that the container's network can reach.

## What is in the image

```bash
docker run --rm pqc-probe cat /opt/pqc-probe/VERSIONS
```

The service runs as the unprivileged user `pqc` (uid 10001). Tool paths are set through the
same variables as on a workstation: `PQC_PROBE_OPENSSL`, `PQC_PROBE_OPENSSL_OQS`,
`PQC_PROBE_SSH`, `PQC_PROBE_SSH_OQS`.
