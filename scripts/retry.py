#!/usr/bin/env python3
"""
Phase 6 retry + classification passes for the Tranco scan.

The first pass (concurrency 50 = up to 350 parallel openssl processes) produced
two kinds of suspect rows:
  * failures that hit the 5s timeout (amazon.com, linkedin.com, baidu.com ...)
  * "classical-only" rows where the probe ran ~5s, i.e. at least one KEM attempt
    probably timed out — possible false negatives for X25519MLKEM768.

Workflow (run from the pqc-probe repo root):

  # 1. Build the retry list from pass 1
  python3 retry.py prepare results/scan.csv results/retry-1.csv

  # 2. Re-probe gently
  PQC_PROBE_OPENSSL=/opt/openssl-3.5/bin/openssl ./target/release/pqc-probe scan \
      results/retry-1.csv --output results/retry-1-results.csv --concurrency 10 --timeout 10

  # 3. Still-failing domains -> try www.<domain>
  python3 retry.py www results/scan.csv results/retry-1-results.csv results/retry-www.csv
  PQC_PROBE_OPENSSL=/opt/openssl-3.5/bin/openssl ./target/release/pqc-probe scan \
      results/retry-www.csv --output results/retry-www-results.csv --concurrency 10 --timeout 10

  # 4. Merge all passes + classify what's still failing (TCP / TLS 1.2-only / other)
  python3 retry.py merge results/scan.csv results/retry-1-results.csv \
      results/retry-www-results.csv results/final.csv --openssl /opt/openssl-3.5/bin/openssl

Merge rule: a later pass replaces an earlier row only if the later row is "ok".
Ranks are the join key (domain differs for the www pass).
"""
import argparse
import csv
import socket
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor

import pandas as pd

SUSPECT_MS = 4900  # a row that ran this long had at least one attempt time out


def cmd_prepare(a):
    df = pd.read_csv(a.scan)
    failed = df["status"] != "ok"
    suspect_classical = (df["status"] == "ok") & (~df["has_x25519mlkem768"]) & (
        df["probe_duration_ms"] >= SUSPECT_MS
    )
    out = df[failed | suspect_classical][["rank", "domain"]].sort_values("rank")
    out.to_csv(a.out, header=False, index=False)
    print(f"{len(out)} domains to retry: {failed.sum()} failures + "
          f"{suspect_classical.sum()} suspect classical-only rows -> {a.out}")


def cmd_www(a):
    base = pd.read_csv(a.scan).set_index("rank")
    r1 = pd.read_csv(a.retry1).set_index("rank")
    still = [rk for rk in r1.index if r1.at[rk, "status"] != "ok"
             and base.at[rk, "status"] != "ok"]
    rows = [(rk, "www." + base.at[rk, "domain"]) for rk in sorted(still)
            if not str(base.at[rk, "domain"]).startswith("www.")]
    with open(a.out, "w", newline="") as f:
        csv.writer(f).writerows(rows)
    print(f"{len(rows)} still-failing domains -> www. variants -> {a.out}")


def tcp_open(host, port=443, timeout=3.0):
    try:
        addr = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM)[0][4]
    except socket.gaierror:
        return "dns_fail"
    try:
        with socket.create_connection(addr, timeout=timeout):
            return "open"
    except OSError:
        return "closed"


def tls_any_version(openssl, host, timeout=8.0):
    """Handshake with no version forced; return the negotiated protocol or None.
    Reads stdout until the summary marker, then kills s_client (it can linger)."""
    p = subprocess.Popen(
        [openssl, "s_client", "-4", "-connect", f"{host}:443", "-servername", host],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        text=True, errors="replace",
    )
    proto, deadline = None, time.monotonic() + timeout
    try:
        # line reads block; a watchdog kill bounds the total time
        import threading
        t = threading.Timer(timeout, p.kill); t.start()
        for line in p.stdout:
            s = line.strip()
            if s.startswith("Protocol"):
                proto = s.split(":", 1)[1].strip() or proto
            elif s.startswith("New, ") and ", Cipher is " in s:
                # "New, TLSv1.3, Cipher is ..." (3.0.x TLS 1.3 summary; 3.5 also prints it)
                v = s.split(",")[1].strip()
                if v.startswith("TLS"):
                    proto = proto or v
            if s.startswith("Verify return code") or time.monotonic() > deadline:
                break
        t.cancel()
    finally:
        p.kill(); p.wait()
    return proto


def classify(row, openssl):
    host = row["probe_host"]
    tcp = tcp_open(host)
    if tcp != "open":
        return "no_dns" if tcp == "dns_fail" else "no_443"
    proto = tls_any_version(openssl, host)
    if proto is None:
        return "tls_error"
    if "1.3" in proto:
        return "tls13_unstable"   # works without forcing 1.3; flaky under the probe
    return "tls12_or_older"


def cmd_merge(a):
    base = pd.read_csv(a.scan)
    base["pass"] = "1"
    base["probe_host"] = base["domain"]
    final = base.set_index("rank")

    for label, path in [("retry", a.retry1), ("www", a.retry_www)]:
        if not path:
            continue
        r = pd.read_csv(path)
        replaced = 0
        for _, row in r.iterrows():
            rk = row["rank"]
            if row["status"] == "ok" and rk in final.index:
                prev = final.loc[rk]
                # never let a retry downgrade a PQ=true finding
                if prev["status"] == "ok" and prev["has_x25519mlkem768"] and not row["has_x25519mlkem768"]:
                    continue
                for col in r.columns:
                    if col not in ("rank", "domain"):
                        final.at[rk, col] = row[col]
                final.at[rk, "probe_host"] = row["domain"]
                final.at[rk, "pass"] = label
                replaced += 1
        print(f"{label}: {replaced} rows upgraded from {path}")

    final = final.reset_index()
    final["fail_class"] = ""
    todo = final[final["status"] != "ok"]
    if a.openssl and len(todo):
        print(f"classifying {len(todo)} remaining failures (TCP + any-version TLS)...")
        with ThreadPoolExecutor(max_workers=10) as ex:
            classes = list(ex.map(lambda r: classify(r, a.openssl), [r for _, r in todo.iterrows()]))
        final.loc[todo.index, "fail_class"] = classes
        print(final.loc[todo.index, "fail_class"].value_counts().to_string())
    elif len(todo):
        print("(no --openssl given: skipping failure classification)")

    for col in ("has_x25519mlkem768", "has_mlkem"):
        final[col] = final[col].astype(bool)
    final.to_csv(a.out, index=False)
    ok = (final["status"] == "ok").sum()
    print(f"\nfinal: {ok}/{len(final)} ok, "
          f"{final['has_x25519mlkem768'].sum()} support X25519MLKEM768 -> {a.out}")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("prepare"); p.add_argument("scan"); p.add_argument("out")
    p = sub.add_parser("www"); p.add_argument("scan"); p.add_argument("retry1"); p.add_argument("out")
    p = sub.add_parser("merge"); p.add_argument("scan"); p.add_argument("retry1")
    p.add_argument("retry_www", nargs="?"); p.add_argument("out")
    p.add_argument("--openssl", help="openssl binary for classifying remaining failures")
    a = ap.parse_args()
    {"prepare": cmd_prepare, "www": cmd_www, "merge": cmd_merge}[a.cmd](a)


if __name__ == "__main__":
    main()
