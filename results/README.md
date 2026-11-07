# Phase 6 — Tranco top-1000 PQ TLS survey

- List: Tranco K9YYW, top 1000, scanned 2026-11-06
- Probe: `pqc-probe scan`, OpenSSL 3.5.2, IPv4 only (`-4`), single vantage point (home ISP, Dhaka)
- Passes: pass 1 (concurrency 50, 5s) → retry (10, 10s) → www. fallback → targeted re-probe (1, 15s)
- `pass` column = which pass produced the row; `fail_class` = classification of remaining failures
- `has_x25519mlkem768` = handshake succeeds when that group is offered alone (support, not preference)
- Scripts: `scripts/retry.py`, `scripts/analyze.py`
