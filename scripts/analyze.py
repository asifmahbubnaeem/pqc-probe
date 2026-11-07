#!/usr/bin/env python3
"""
Phase 6 analysis (v2). Reads the scan CSV (pass-1 or retry-merged final.csv)
and prints headline numbers + saves a two-panel chart.

Usage:
    python3 analyze.py results/final.csv --list-id K9YYW --date 2026-11-06

Every percentage states its denominator: "of reachable" (TLS 1.3 handshake
completed) vs "of all N" ranked domains.
"""
import argparse
import sys

try:
    import pandas as pd
    import matplotlib.pyplot as plt
except ImportError:
    print("Install deps: pip install pandas matplotlib")
    sys.exit(1)

# Reference palette (dataviz skill): one accent + neutral inks.
ACCENT = "#2a78d6"      # PQ hybrid supported
NEUTRAL = "#8f8e89"     # classical TLS 1.3
FAINT = "#cfcec9"       # failure categories
INK, INK2, SURFACE = "#0b0b0b", "#52514e", "#fcfcfb"

FAIL_LABELS = {
    "tls12_or_older": "No TLS 1.3 (1.2 or older)",
    "no_443": "Port 443 closed",
    "no_dns": "No IPv4 DNS record",
    "tls_error": "TLS error / other",
    "tls13_unstable": "TLS 1.3, unstable under probe",
    "": "No handshake (unclassified)",
}


def pct(n, d):
    return f"{100 * n / d:.1f}%" if d else "n/a"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("csv")
    ap.add_argument("--list-id", default="?")
    ap.add_argument("--date", default="?")
    a = ap.parse_args()

    df = pd.read_csv(a.csv, keep_default_na=False)
    for col in ("has_x25519mlkem768", "has_mlkem"):
        df[col] = df[col].astype(str).str.lower() == "true"
    if "fail_class" not in df.columns:
        df["fail_class"] = ""

    total = len(df)
    ok = df[df["status"] == "ok"]
    n_ok = len(ok)
    pq = int(ok["has_x25519mlkem768"].sum())
    mlkem_any = int(ok["has_mlkem"].sum())
    mlkem_other_only = int((ok["has_mlkem"] & ~ok["has_x25519mlkem768"]).sum())
    classical = n_ok - pq

    print(f"\n=== PQ TLS survey — Tranco top {total} (list {a.list_id}, {a.date}), IPv4 ===\n")
    print(f"TLS 1.3 handshake completed: {n_ok:>5}  ({pct(n_ok, total)} of all {total})")
    print(f"No handshake:                {total - n_ok:>5}  ({pct(total - n_ok, total)})")
    fails = df[df["status"] != "ok"]["fail_class"].value_counts()
    for k, v in fails.items():
        print(f"    {FAIL_LABELS.get(k, k):<34} {v:>5}")

    print(f"\nSupport X25519MLKEM768: {pq:>5}  = {pct(pq, n_ok)} of reachable, {pct(pq, total)} of all {total}")
    print(f"Any ML-KEM hybrid:      {mlkem_any:>5}  (ML-KEM without X25519MLKEM768: {mlkem_other_only})")
    print(f"Classical-only TLS 1.3: {classical:>5}  = {pct(classical, n_ok)} of reachable")

    print("\nOther hybrid groups accepted (of reachable):")
    for g in ("SecP256r1MLKEM768", "SecP384r1MLKEM1024"):
        n = int(ok["kems_negotiated"].str.contains(g, regex=False).sum())
        print(f"  {g:<22} {n:>5}  ({pct(n, n_ok)})")
    no_x25519 = int((~ok["kems_negotiated"].str.split(";").apply(lambda ks: "X25519" in ks)).sum())
    print(f"  (no plain X25519 at all: {no_x25519} — NIST-curves-only stacks)")

    print("\nPQ support by rank bucket (of reachable in bucket):")
    for lo, hi in [(1, 100), (101, 500), (501, 1000)]:
        b = ok[(ok["rank"] >= lo) & (ok["rank"] <= hi)]
        if len(b):
            n = int(b["has_x25519mlkem768"].sum())
            print(f"  Rank {lo:>4}-{hi:<4} {n:>4}/{len(b):<4} {pct(n, len(b)):>6}")

    print("\nLeaf cert signature algorithm (CA's signature on the leaf, of reachable):")
    sig = ok["cert_sig_alg"].replace("", "(unparsed)").value_counts()
    for alg, n in sig.head(8).items():
        print(f"  {alg:<32} {n:>5}  ({pct(n, n_ok)})")
    print(f"  PQ (ML-DSA / SLH-DSA) signatures: "
          f"{int(ok['cert_sig_alg'].str.contains('ML-DSA|SLH-DSA|mldsa|slhdsa', case=False).sum())}")

    if "pass" in df.columns:
        print("\nRows by probe pass:", df["pass"].value_counts().to_dict())

    # ---------- chart ----------
    plt.rcParams.update({"font.size": 10, "axes.edgecolor": FAINT, "axes.labelcolor": INK2,
                         "xtick.color": INK2, "ytick.color": INK2, "text.color": INK})
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(13, 5), facecolor=SURFACE,
                                   gridspec_kw={"width_ratios": [1.15, 1]})

    cats = [("Supports X25519MLKEM768", pq, ACCENT), ("Classical-only TLS 1.3", classical, NEUTRAL)]
    for k, v in fails.items():
        cats.append((FAIL_LABELS.get(k, k), int(v), FAINT))
    labels, vals, cols = zip(*cats)
    y = range(len(cats))[::-1]
    ax1.barh(list(y), vals, color=cols, height=0.62)
    ax1.set_yticks(list(y)); ax1.set_yticklabels(labels)
    for yi, v, i in zip(y, vals, range(len(vals))):
        note = f"{v}  ({pct(v, n_ok)} of reachable)" if i < 2 else f"{v}"
        ax1.text(v + total * 0.01, yi, note, va="center", color=INK2, fontsize=9)
    ax1.set_xlim(0, max(vals) * 1.45)
    ax1.set_xlabel(f"Domains (of {total})")
    ax1.set_title(f"Outcome per domain — {n_ok} of {total} completed a TLS 1.3 handshake",
                  loc="left", fontsize=11)

    top = sig.head(6)[::-1]
    ax2.barh(top.index, top.values, color=ACCENT, height=0.62)
    for yi, v in enumerate(top.values):
        ax2.text(v + n_ok * 0.01, yi, f"{v}  ({pct(v, n_ok)})", va="center", color=INK2, fontsize=9)
    ax2.set_xlim(0, top.max() * 1.35)
    ax2.set_xlabel(f"Domains (of {n_ok} reachable)")
    ax2.set_title("Leaf certificate signature algorithm — zero post-quantum", loc="left", fontsize=11)

    for ax in (ax1, ax2):
        ax.set_facecolor(SURFACE)
        for s in ("top", "right"):
            ax.spines[s].set_visible(False)
        ax.tick_params(length=0)

    fig.suptitle(f"Post-quantum TLS on the Tranco top {total}  ·  list {a.list_id}  ·  {a.date}  ·  IPv4",
                 x=0.01, ha="left", fontsize=12, fontweight="bold")
    plt.tight_layout(rect=(0, 0, 1, 0.95))
    out = a.csv.rsplit(".", 1)[0] + "-charts.png"
    plt.savefig(out, dpi=150, bbox_inches="tight", facecolor=SURFACE)
    print(f"\nChart saved to {out}")


if __name__ == "__main__":
    main()
