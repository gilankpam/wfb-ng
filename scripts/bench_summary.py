#!/usr/bin/env python3
"""Summarize a fec_bench CSV for human reading.

Input format: the CSV written by src/bench/fec_bench.cpp. See
bench/README.md for the schema. One row per (model, params, k, n, seed).

This script aggregates across seeds (mean), pivots by loss parameter
within each channel model, and prints a series of small tables.

Phase 0: no interleaver, so no `depth` column and no A/B comparison.
A follow-up in the Phase 1 PR will extend this script to diff a new
CSV against bench/baseline.csv.

Python 3 stdlib only -- no numpy, no pandas.
"""

from __future__ import annotations

import argparse
import csv
import statistics
import sys
from collections import defaultdict


def load(path):
    with open(path, newline="") as fh:
        reader = csv.DictReader(fh)
        rows = list(reader)
    # Coerce numeric columns.
    numeric_float = (
        "param1", "param2",
        "block_recovery_rate", "residual_packet_loss",
        "encode_us_mean", "encode_us_p99",
        "decode_us_mean", "decode_us_p99",
    )
    numeric_int = ("k", "n", "blocks", "peak_mem_bytes")
    for r in rows:
        for col in numeric_float:
            v = r.get(col, "")
            r[col] = float(v) if v not in ("", None) else None
        for col in numeric_int:
            v = r.get(col, "")
            r[col] = int(v) if v not in ("", None) else None
    return rows


def mean(vs):
    vs = [v for v in vs if v is not None]
    return statistics.fmean(vs) if vs else None


def fmt_pct(v):
    return f"{v * 100:6.2f}%" if v is not None else "     --"


def fmt_us(v):
    return f"{v:7.2f}" if v is not None else "     --"


def fmt_int(v):
    return f"{v:>10d}" if v is not None else "        --"


def pivot_recovery(rows, model, param_keys):
    """Group rows where channel_model == model by (k,n,*param_keys), aggregating
    block_recovery_rate across seeds. Returns {(k,n): {param_tuple: mean_recov}}.
    param_keys is a list of field names (e.g. ["param1"] or ["param1","param2"]).
    """
    by_kn = defaultdict(lambda: defaultdict(list))
    for r in rows:
        if r["channel_model"] != model:
            continue
        kn = (r["k"], r["n"])
        key = tuple(r[k] for k in param_keys)
        by_kn[kn][key].append(r["block_recovery_rate"])
    out = {}
    for kn, buckets in by_kn.items():
        out[kn] = {k: mean(vs) for k, vs in buckets.items()}
    return out


def print_uniform_table(rows):
    pivot = pivot_recovery(rows, "uniform", ["param1"])
    if not pivot:
        return
    all_ps = sorted({p for kn in pivot.values() for (p,) in kn.keys()})
    print()
    print("--- Recovery rate (uniform loss, mean across seeds) ---")
    header = "(k,n)".ljust(10) + "".join(f"p={p:<8.4g}".ljust(12) for p in all_ps)
    print(header)
    for kn in sorted(pivot):
        k, n = kn
        row = f"({k},{n})".ljust(10)
        for p in all_ps:
            v = pivot[kn].get((p,))
            row += fmt_pct(v).ljust(12)
        print(row)


def print_ge_tables(rows):
    pivot = pivot_recovery(rows, "ge", ["param1", "param2"])
    if not pivot:
        return
    gap_values = sorted({gap for kn in pivot.values() for (_b, gap) in kn.keys()})
    for gap in gap_values:
        all_bursts = sorted({b for kn in pivot.values() for (b, g) in kn.keys() if g == gap})
        print()
        print(f"--- Recovery rate (Gilbert-Elliott, gap_mean={gap:g}, mean across seeds) ---")
        header = "(k,n)".ljust(10) + "".join(
            f"burst={b:<6.4g}".ljust(14) for b in all_bursts
        )
        print(header)
        for kn in sorted(pivot):
            k, n = kn
            row = f"({k},{n})".ljust(10)
            for b in all_bursts:
                v = pivot[kn].get((b, gap))
                row += fmt_pct(v).ljust(14)
            print(row)


def print_periodic_table(rows):
    pivot = pivot_recovery(rows, "periodic", ["param1", "param2"])
    if not pivot:
        return
    # One table per burst_len (param2).
    burst_lens = sorted({bl for kn in pivot.values() for (_p, bl) in kn.keys()})
    for bl in burst_lens:
        all_periods = sorted({p for kn in pivot.values() for (p, b) in kn.keys() if b == bl})
        print()
        print(f"--- Recovery rate (periodic, burst_len={bl:g}, mean across seeds) ---")
        header = "(k,n)".ljust(10) + "".join(f"P={p:<8.4g}".ljust(12) for p in all_periods)
        print(header)
        for kn in sorted(pivot):
            k, n = kn
            row = f"({k},{n})".ljust(10)
            for p in all_periods:
                v = pivot[kn].get((p, bl))
                row += fmt_pct(v).ljust(12)
            print(row)


def print_cpu_table(rows):
    # Per (k,n) aggregate: mean-of-means for encode/decode, max-of-p99 for the
    # tail column (so a per-config p99 never gets diluted by averaging).
    by_kn = defaultdict(lambda: {
        "enc_mean": [], "enc_p99": [],
        "dec_mean": [], "dec_p99": [],
        "mem": [],
    })
    for r in rows:
        kn = (r["k"], r["n"])
        by_kn[kn]["enc_mean"].append(r["encode_us_mean"])
        by_kn[kn]["enc_p99"].append(r["encode_us_p99"])
        if r["decode_us_mean"] is not None:
            by_kn[kn]["dec_mean"].append(r["decode_us_mean"])
            by_kn[kn]["dec_p99"].append(r["decode_us_p99"])
        by_kn[kn]["mem"].append(r["peak_mem_bytes"])

    if not by_kn:
        return
    print()
    print("--- CPU cost per block, microseconds (across all configs of each (k,n)) ---")
    print("(k,n)".ljust(10)
          + "enc_mean".rjust(10)
          + "enc_p99_max".rjust(14)
          + "dec_mean".rjust(12)
          + "dec_p99_max".rjust(14))
    for kn in sorted(by_kn):
        k, n = kn
        agg = by_kn[kn]
        enc_mean = mean(agg["enc_mean"])
        enc_p99  = max(agg["enc_p99"]) if agg["enc_p99"] else None
        dec_mean = mean(agg["dec_mean"])
        dec_p99  = max(agg["dec_p99"]) if agg["dec_p99"] else None
        print(f"({k},{n})".ljust(10)
              + fmt_us(enc_mean).rjust(10)
              + fmt_us(enc_p99).rjust(14)
              + fmt_us(dec_mean).rjust(12)
              + fmt_us(dec_p99).rjust(14))


def print_memory_table(rows):
    by_kn = defaultdict(list)
    for r in rows:
        by_kn[(r["k"], r["n"])].append(r["peak_mem_bytes"])
    if not by_kn:
        return
    print()
    print("--- Peak explicit heap per config, bytes ---")
    print("(k,n)".ljust(10) + "bytes".rjust(14))
    for kn in sorted(by_kn):
        k, n = kn
        vals = [v for v in by_kn[kn] if v is not None]
        if not vals:
            continue
        # Should be constant per (k,n) within the same preset; sanity check.
        v = max(vals)
        print(f"({k},{n})".ljust(10) + f"{v:>14d}")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("csv_path", help="CSV written by fec_bench --sweep ...")
    args = ap.parse_args()

    rows = load(args.csv_path)
    if not rows:
        print(f"{args.csv_path}: no rows", file=sys.stderr)
        return 1

    kn_pairs = sorted({(r["k"], r["n"]) for r in rows})
    models   = sorted({r["channel_model"] for r in rows})
    seeds    = sorted({r["seed"] for r in rows})

    print(f"=== fec_bench summary: {args.csv_path} ===")
    print(f"rows={len(rows)} "
          f"(k,n)={len(kn_pairs)} pairs "
          f"models={models} "
          f"seeds={len(seeds)}")

    print_uniform_table(rows)
    print_ge_tables(rows)
    print_periodic_table(rows)
    print_cpu_table(rows)
    print_memory_table(rows)
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
