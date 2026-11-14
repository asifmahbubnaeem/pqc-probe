#!/usr/bin/env python3
"""Load test for a locally running pqc-probe-web. Standard library only.

It is deliberately polite to the outside world: phase 1 makes no probes at all, and phases 2-3
start at most one real probe (against --target, default example.com).

  1. HTTP layer: many concurrent GETs of /healthz and /api/v1/meta. Reports throughput and
     latency percentiles; any 5xx or connection error is a failure.
  2. Duplicate race: --dupes identical POSTs at the same moment. Every 202 must carry the same
     job id (the cooldown reuse must be atomic); the rest may be 429. A 5xx is a failure.
  3. Polling flood: many concurrent GETs of that job's status. Expect 200s, then 429s with
     Retry-After; any 5xx is a failure.

Usage: start the server with default limits, then
  python3 scripts/loadtest.py [--base http://127.0.0.1:8080] [--requests 2000] [--concurrency 32]
Exit status 0 if every check passed.
"""
import argparse
import json
import sys
import threading
import time
import urllib.error
import urllib.request
from collections import Counter
from concurrent.futures import ThreadPoolExecutor


def request(method, url, body=None, timeout=30):
    """Returns (status or None, headers dict, parsed JSON or None, seconds, error text)."""
    data = None
    headers = {}
    if body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    t = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw, status, hdrs = r.read(), r.status, dict(r.headers)
    except urllib.error.HTTPError as e:
        raw, status, hdrs = e.read(), e.code, dict(e.headers)
    except Exception as e:  # connection refused, reset, timeout
        return None, {}, None, time.perf_counter() - t, f"{type(e).__name__}: {e}"
    elapsed = time.perf_counter() - t
    try:
        parsed = json.loads(raw) if raw else None
    except ValueError:
        parsed = None
    return status, {k.lower(): v for k, v in hdrs.items()}, parsed, elapsed, None


def pct(sorted_values, p):
    if not sorted_values:
        return float("nan")
    i = min(len(sorted_values) - 1, int(round(p / 100 * (len(sorted_values) - 1))))
    return sorted_values[i]


def summarize(name, results, wall):
    codes = Counter(r[0] if r[0] is not None else "error" for r in results)
    lat = sorted(r[3] * 1000 for r in results if r[0] is not None)
    errors = [r[4] for r in results if r[4]]
    print(f"  {name}: {len(results)} requests in {wall:.2f}s ({len(results) / wall:.0f}/s)")
    print(f"    status codes: {dict(sorted(codes.items(), key=lambda kv: str(kv[0])))}")
    if lat:
        print(f"    latency ms: p50 {pct(lat, 50):.1f}  p95 {pct(lat, 95):.1f}  "
              f"p99 {pct(lat, 99):.1f}  max {lat[-1]:.1f}")
    if errors:
        print(f"    first error: {errors[0]}")
    return codes


def fan_out(n, concurrency, fn):
    """Run fn(i) n times on `concurrency` threads, started together. Returns (results, wall)."""
    start = threading.Barrier(min(n, concurrency))
    first_wave = set(range(min(n, concurrency)))

    def run(i):
        if i in first_wave:
            start.wait()
        return fn(i)

    t = time.perf_counter()
    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        results = list(pool.map(run, range(n)))
    return results, time.perf_counter() - t


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--base", default="http://127.0.0.1:8080")
    ap.add_argument("--requests", type=int, default=2000, help="phase 1 request count")
    ap.add_argument("--concurrency", type=int, default=32)
    ap.add_argument("--target", default="example.com", help="the one real host phases 2-3 probe")
    ap.add_argument("--dupes", type=int, default=20, help="identical POSTs in phase 2")
    ap.add_argument("--polls", type=int, default=300, help="status GETs in phase 3")
    ap.add_argument("--skip-probe", action="store_true", help="run phase 1 only (no real probe)")
    a = ap.parse_args()
    base = a.base.rstrip("/")
    failures = []

    status, _, meta, _, err = request("GET", base + "/api/v1/meta")
    if status != 200:
        sys.exit(f"cannot reach {base}/api/v1/meta: {err or status}")
    print(f"server: pqc-probe {meta['tool']['version']}, limits {meta.get('rate_limits')}")

    # ---- phase 1
    print("\nphase 1: HTTP layer (no probes)")
    paths = ["/healthz", "/api/v1/meta"]
    results, wall = fan_out(a.requests, a.concurrency,
                            lambda i: request("GET", base + paths[i % 2]))
    codes = summarize("GET /healthz + /api/v1/meta", results, wall)
    bad = {c: n for c, n in codes.items() if c == "error" or (isinstance(c, int) and c != 200)}
    if bad:
        failures.append(f"phase 1: unexpected responses {bad}")

    if a.skip_probe:
        return report(failures)

    # ---- phase 2
    print(f"\nphase 2: {a.dupes} identical submissions at once (target {a.target})")
    body = {"target": a.target, "protocol": "tls", "mode": "vanilla"}
    results, wall = fan_out(a.dupes, a.dupes, lambda i: request("POST", base + "/api/v1/probes", body))
    codes = summarize("POST /api/v1/probes", results, wall)
    ids = {r[2]["id"] for r in results if r[0] == 202 and r[2]}
    reused = sum(1 for r in results if r[0] == 202 and r[2] and r[2].get("reused"))
    other = {c: n for c, n in codes.items() if c not in (202, 429)}
    print(f"    distinct job ids among 202s: {len(ids)} ({reused} marked reused)")
    if other:
        failures.append(f"phase 2: unexpected responses {other}")
    if len(ids) != 1:
        failures.append(f"phase 2: expected exactly one job id, got {len(ids)}: {sorted(ids)}")
    if not ids:
        return report(failures)
    job = next(iter(ids))

    # ---- phase 3
    print(f"\nphase 3: polling flood ({a.polls} status requests)")
    url = f"{base}/api/v1/probes/{job}"
    results, wall = fan_out(a.polls, a.concurrency, lambda i: request("GET", url))
    codes = summarize("GET /api/v1/probes/{id}", results, wall)
    other = {c: n for c, n in codes.items() if c not in (200, 429)}
    if other:
        failures.append(f"phase 3: unexpected responses {other}")
    limited = [r for r in results if r[0] == 429]
    if not limited:
        failures.append("phase 3: no 429 at all; the poll limit did not engage")
    elif not all("retry-after" in r[1] for r in limited):
        failures.append("phase 3: a 429 without Retry-After")

    # Let the probe finish so the run leaves no work behind, and show its outcome.
    deadline = time.time() + 60
    final = None
    while time.time() < deadline:
        time.sleep(3)  # stay under the poll budget while it refills
        s, _, v, _, _ = request("GET", url)
        if s == 200 and v and v["status"] in ("succeeded", "failed", "timed_out"):
            final = v["status"]
            break
    print(f"\nthe one real probe ended as: {final or 'still running after 60 s'}")
    return report(failures)


def report(failures):
    print()
    if failures:
        for f in failures:
            print("FAIL", f)
        print("## LOADTEST: FAIL")
        return 1
    print("## LOADTEST: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
