# pqc-probe-web

HTTP service around the same probe as the CLI. **Status: skeleton.** Job handling, validation,
limits and the JSON API work and are tested against fakes; the real probe is not wired in yet,
so every job currently fails with "probing is not wired into the web service yet".

## Run

```
cargo run -p pqc-probe-web          # listens on 127.0.0.1:8080
```

Configuration (environment variables, all optional):

| Variable | Default | Meaning |
|---|---|---|
| `PQC_WEB_BIND` | `127.0.0.1:8080` | Listen address. Loopback by default; put a reverse proxy in front. |
| `PQC_WEB_MAX_CONCURRENT` | `4` | Probes running at once (1-64). |
| `PQC_WEB_QUEUE_LIMIT` | `50` | Jobs queued or running; more get `503 busy`. Must be >= max concurrent. |
| `PQC_WEB_JOB_TIMEOUT_SECS` | `90` | Deadline for one probe once it starts (1-600). |
| `PQC_WEB_RESULT_TTL_SECS` | `3600` | How long a finished job and its report are kept. |
| `PQC_WEB_ALLOWED_PORTS` | `22,443,465,636,853,993,995,2222,8443` | Ports a probe may target. |

## API (`/api/v1`)

| Method and path | Meaning |
|---|---|
| `POST /probes` | Submit `{"target":"host[:port]","protocol":"tls\|ssh\|both","mode":"vanilla\|experimental\|both","tls_port":443,"ssh_port":22}`. Only `target` is required (`protocol` defaults to `tls`, `mode` to `both`). Returns `202` with `id`, `status_url`, `report_url`. |
| `GET /probes/{id}` | Job status: `queued`, `running`, `succeeded`, `failed`, `timed_out`. |
| `GET /probes/{id}/report` | The report, identical to `pqc-probe probe --output json` (schema: `schema/report-v1.json`). `409` while running, or if the job failed. |
| `GET /meta` | Tool version, schema version, allowed ports, limits. |
| `GET /healthz`, `GET /readyz` | Liveness; readiness (`503` when the queue is full). |

Ports: the port in `target` is the TLS port, unless `protocol` is `ssh`, in which case it is the
SSH port. `tls_port` / `ssh_port` override.

Errors are `{"error":{"code":"...","message":"...","hint":null}}`. Stable codes:
`invalid_request` (400), `unsupported_media_type` (415), `payload_too_large` (413),
`invalid_target` (400), `port_not_allowed` (400), `unresolvable_target` (400),
`target_not_allowed` (403), `busy` (503, with `Retry-After`), `not_found` (404),
`not_ready` (409, with `Retry-After`), `job_failed` (409), `job_timed_out` (409).

## What protects the targets and the service

- Private, loopback, link-local, metadata and other non-public addresses are refused. DNS is
  resolved once, every address is checked, and the probe connects to the checked address.
- Only allowlisted ports; strict host syntax.
- Global concurrency cap, bounded queue, per-job deadline, result expiry.
- Job ids are random (122 bits) and are the only access control on results: do not publish them.

Not done yet (next steps): the real prober, per-IP and per-target rate limits, the HTML report
page, security headers, the threat-model document.

## Note for operators

Probing connects to the target several times. OpenSSH 9.8+ servers penalize sources that
connect and drop before authenticating (`PerSourcePenalties`) and may refuse this service's IP
for a while. The SSH probe is paced for that reason; keep the per-target limits in place.
