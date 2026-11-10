# JSON report schema (v1)

`pqc-probe probe … --output json` prints one JSON document. The web API returns the same
document. Other tools (for example the planned Migration Dashboard) depend on it, so it is a
**public contract**.

- Machine-readable schema: [`schema/report-v1.json`](../schema/report-v1.json), generated from the
  Rust types in `crates/pqc-probe-core/src/report.rs`.
- A unit test (`committed_schema_matches_types`) fails if the committed file and the types
  disagree, so the schema cannot drift silently.

## Shape

```json
{
  "schema_version": 1,
  "tool": { "name": "pqc-probe", "version": "0.1.0" },
  "generated_at": "2026-11-09T14:20:00Z",
  "target":  { "input": "github.com:443", "host": "github.com", "tls_port": 443, "ssh_port": 22 },
  "request": { "protocol": "both", "mode": "both" },
  "tls": {
    "vanilla":      { "...": "TlsReport or null" },
    "experimental": { "...": "TlsReport or null" },
    "diff":         { "only_vanilla": [], "only_experimental": [], "in_both": [] },
    "errors":       { "vanilla": null, "experimental": null }
  },
  "ssh": { "vanilla": {}, "experimental": {}, "diff": {}, "errors": {} }
}
```

- `tls` / `ssh` are `null` when that protocol was not requested.
- `vanilla` / `experimental` are `null` when that stack was not requested **or** its probe failed;
  a failure says why in `errors`.
- `diff` is `null` unless both sides produced a result.
- `tls.vanilla_pq_capable` is `true` when the stock OpenSSL client itself completed a post-quantum
  handshake (OpenSSL 3.5 or newer). The vanilla-vs-experimental TLS diff then says little about the
  server. It is `null` when the stock client did not run or failed.
- Every key is always present. `null` means "not applicable, not run, or failed" and never
  "unknown, assume nothing happened": check `errors`.
- `request.protocol`: `tls | ssh | both`. `request.mode`: `vanilla | experimental | both`.

## Compatibility rules

| Change | Allowed in v1? |
|---|---|
| Add a new field | Yes (minor). Consumers must ignore unknown fields. In the schema a new field is **optional** (not in `required`) so documents from older versions still validate; existing fields are all `required`. |
| Add a new value to a documented string enum | Yes, but consumers must tolerate unknown values. |
| Remove or rename a field | No: bumps `schema_version` to 2 and ships `schema/report-v2.json` plus a migration note. |
| Change a field's type or meaning | No: same as above. |
| Reorder keys / change whitespace | Not part of the contract. |

When the types change compatibly, regenerate the schema and commit it with the change:

```
UPDATE_SCHEMA=1 cargo test -p pqc-probe-core committed_schema_matches_types
```

## Notes for consumers

- `server_offered_kex` includes protocol markers such as `kex-strict-s-v00@openssh.com` and
  `ext-info-s`; they are not key-exchange algorithms. The human output hides them, the JSON keeps
  them for completeness.
- `diff.mainline_since` (SSH) maps an OQS-only algorithm to the first stock OpenSSH release that
  also has it. Algorithms missing from that map are genuinely OQS-only.
- Some servers randomize their SSH version string (GitHub does); don't treat `server_version` as a
  stable identifier.
- `cert_chain` lists what the server *sent*. Servers normally omit the root, so the last entry is
  usually an intermediate (`self_signed: false`).
