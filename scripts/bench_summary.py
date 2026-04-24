#!/usr/bin/env python3
"""Summarize a fec_bench CSV for human reading.

Input format: the CSV written by src/bench/fec_bench.cpp. See
bench/README.md for the schema.

Two CSV schemas are accepted:
  - Phase 0 baseline.csv (no `depth` column) -- every row is treated
    as depth=1.
  - Phase 0.5+ interleaved.csv (with `depth` column).

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
        has_depth = "depth" in (reader.fieldnames or [])
        rows = list(reader)
    numeric_float = (
        "param1", "param2",
        "block_recovery_rate", "residual_packet_loss",
        "encode_us_mean", "encode_us_p99",
        "decode_us_mean", "decode_us_p99",
    )
    numeric_int = ("k", "n", "blocks", "peak_mem_bytes")
    # latency_ms is a v2.1 addition; treat as optional.
    numeric_optional_float = ("latency_ms",)
    for r in rows:
        for col in numeric_float:
            v = r.get(col, "")
            r[col] = float(v) if v not in ("", None) else None
        for col in numeric_int:
            v = r.get(col, "")
            r[col] = int(v) if v not in ("", None) else None
        for col in numeric_optional_float:
            v = r.get(col, "")
            r[col] = float(v) if v not in ("", None) else None
        # Normalize depth.
        if has_depth:
            r["depth"] = int(r["depth"])
        else:
            r["depth"] = 1
    return rows


def mean(vs):
    vs = [v for v in vs if v is not None]
    return statistics.fmean(vs) if vs else None


def fmt_pct(v):
    return f"{v * 100:6.2f}%" if v is not None else "     --"


def fmt_us(v):
    return f"{v:7.2f}" if v is not None else "     --"


def kn_d_label(kn, d):
    k, n = kn
    return f"({k},{n}) D={d}"


def pivot_recovery(rows, model, param_keys):
    """Group by (k, n, depth, *param_keys). Recovery rate is averaged
    across seeds. Returns
    {(k, n, depth): {param_tuple: mean_recov}}.
    """
    by_knd = defaultdict(lambda: defaultdict(list))
    for r in rows:
        if r["channel_model"] != model:
            continue
        key_knd = (r["k"], r["n"], r["depth"])
        param_key = tuple(r[k] for k in param_keys)
        by_knd[key_knd][param_key].append(r["block_recovery_rate"])
    return {knd: {pk: mean(vs) for pk, vs in buckets.items()}
            for knd, buckets in by_knd.items()}


def print_recovery_table(title, rows, model, param_keys,
                         param_label_fmt, param_label_width):
    """Generic table: rows = (k,n,D), columns = channel params.
    """
    pivot = pivot_recovery(rows, model, param_keys)
    if not pivot:
        return
    all_params = sorted({p for b in pivot.values() for p in b.keys()})
    if not all_params:
        return

    print()
    print(f"--- {title} ---")
    header = "cfg".ljust(18) + "".join(
        param_label_fmt(p).ljust(param_label_width) for p in all_params
    )
    print(header)

    # Sort rows: by (k, n, D). depth grouped together per (k, n).
    for knd in sorted(pivot):
        k, n, d = knd
        label = kn_d_label((k, n), d)
        line = label.ljust(18)
        for p in all_params:
            line += fmt_pct(pivot[knd].get(p)).ljust(param_label_width)
        print(line)


def print_uniform(rows):
    print_recovery_table(
        title="Recovery rate: uniform loss (mean across seeds)",
        rows=rows,
        model="uniform",
        param_keys=["param1"],
        param_label_fmt=lambda p: f"p={p[0]:<.4g}",
        param_label_width=12,
    )


def print_ge(rows):
    # One sub-table per gap value.
    pivot = pivot_recovery(rows, "ge", ["param1", "param2"])
    if not pivot:
        return
    gaps = sorted({gap for b in pivot.values() for (_bm, gap) in b.keys()})
    for gap in gaps:
        # Re-key to keep only rows with this gap.
        sub_rows = [r for r in rows if r["channel_model"] == "ge" and r["param2"] == gap]
        print_recovery_table(
            title=f"Recovery rate: Gilbert-Elliott gap_mean={gap:g}",
            rows=sub_rows,
            model="ge",
            param_keys=["param1"],
            param_label_fmt=lambda bm: f"burst={bm[0]:<.4g}",
            param_label_width=14,
        )


def print_periodic(rows):
    pivot = pivot_recovery(rows, "periodic", ["param1", "param2"])
    if not pivot:
        return
    burst_lens = sorted({bl for b in pivot.values() for (_p, bl) in b.keys()})
    for bl in burst_lens:
        sub_rows = [r for r in rows if r["channel_model"] == "periodic" and r["param2"] == bl]
        print_recovery_table(
            title=f"Recovery rate: periodic burst_len={bl:g}",
            rows=sub_rows,
            model="periodic",
            param_keys=["param1"],
            param_label_fmt=lambda p: f"P={p[0]:<.4g}",
            param_label_width=12,
        )


def print_cpu_table(rows):
    """Per (k,n,D): encode mean + max p99, decode mean + max p99."""
    agg = defaultdict(lambda: {
        "enc_mean": [], "enc_p99": [],
        "dec_mean": [], "dec_p99": [],
    })
    for r in rows:
        key = (r["k"], r["n"], r["depth"])
        agg[key]["enc_mean"].append(r["encode_us_mean"])
        agg[key]["enc_p99"].append(r["encode_us_p99"])
        if r["decode_us_mean"] is not None:
            agg[key]["dec_mean"].append(r["decode_us_mean"])
            agg[key]["dec_p99"].append(r["decode_us_p99"])
    if not agg:
        return
    print()
    print("--- CPU cost per block, microseconds ---")
    print("cfg".ljust(18)
          + "enc_mean".rjust(10)
          + "enc_p99_max".rjust(14)
          + "dec_mean".rjust(12)
          + "dec_p99_max".rjust(14))
    for key in sorted(agg):
        k, n, d = key
        label = kn_d_label((k, n), d)
        a = agg[key]
        enc_mean = mean(a["enc_mean"])
        enc_p99  = max(a["enc_p99"]) if a["enc_p99"] else None
        dec_mean = mean(a["dec_mean"])
        dec_p99  = max(a["dec_p99"]) if a["dec_p99"] else None
        print(label.ljust(18)
              + fmt_us(enc_mean).rjust(10)
              + fmt_us(enc_p99).rjust(14)
              + fmt_us(dec_mean).rjust(12)
              + fmt_us(dec_p99).rjust(14))


def print_latency_table(rows):
    """Modeled latency per (k,n,D) from the plan §4.2 formula. All
    rows for the same (k,n,D) have identical latency_ms by design
    (it's a function of k,n,D + timing assumptions); we just pull
    the first non-None value.
    """
    seen = {}
    for r in rows:
        lat = r.get("latency_ms")
        if lat is None:
            continue
        key = (r["k"], r["n"], r["depth"])
        seen.setdefault(key, lat)
    if not seen:
        return
    print()
    print("--- Modeled delivery latency (ms), per plan §4.2 ---")
    print("cfg".ljust(18) + "latency_ms".rjust(12))
    for key in sorted(seen):
        k, n, d = key
        print(kn_d_label((k, n), d).ljust(18) + f"{seen[key]:>12.2f}")


def print_memory_table(rows):
    by_kn_d = defaultdict(list)
    for r in rows:
        by_kn_d[(r["k"], r["n"], r["depth"])].append(r["peak_mem_bytes"])
    if not by_kn_d:
        return
    print()
    print("--- Peak explicit heap per config, bytes ---")
    print("cfg".ljust(18) + "bytes".rjust(14))
    for key in sorted(by_kn_d):
        k, n, d = key
        vals = [v for v in by_kn_d[key] if v is not None]
        if not vals:
            continue
        v = max(vals)
        print(kn_d_label((k, n), d).ljust(18) + f"{v:>14d}")


def print_burst_improvement(rows):
    """Plan §3.6 Y_burst bar: at GE burst=5, gap=100, D=4 recovery
    must be >= 3x the baseline (D=1) recovery *improvement* over 1.0.
    """
    relevant = [r for r in rows
                if r["channel_model"] == "ge"
                and r["param1"] == 5.0 and r["param2"] == 100.0
                and r["depth"] in (1, 4)]
    if not relevant:
        return
    by_kn = defaultdict(lambda: {})
    for r in relevant:
        by_kn[(r["k"], r["n"])][r["depth"]] = r["block_recovery_rate"]
    if not by_kn:
        return
    print()
    print("--- §3.6 Y_burst indicator (GE burst=5, gap=100; D=4 vs D=1) ---")
    print("cfg".ljust(12)
          + "D=1 recov".rjust(12)
          + "D=4 recov".rjust(12)
          + "loss(1)".rjust(10)
          + "loss(4)".rjust(10)
          + "loss_ratio".rjust(12)
          + "verdict".rjust(12))
    for kn in sorted(by_kn):
        k, n = kn
        a = by_kn[kn].get(1)
        b = by_kn[kn].get(4)
        if a is None or b is None:
            continue
        loss_a = 1.0 - a
        loss_b = 1.0 - b
        # "3x better" framed as: loss at D=4 should be <= 1/3 of loss at D=1.
        ratio = (loss_a / loss_b) if loss_b > 0 else float("inf")
        verdict = "PASS" if ratio >= 3.0 else "FAIL"
        print(f"({k},{n})".ljust(12)
              + fmt_pct(a).rjust(12)
              + fmt_pct(b).rjust(12)
              + fmt_pct(loss_a).rjust(10)
              + fmt_pct(loss_b).rjust(10)
              + f"{ratio:>10.2f}x".rjust(12)
              + verdict.rjust(12))


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("csv_path", help="CSV written by fec_bench --sweep ...")
    args = ap.parse_args()

    rows = load(args.csv_path)
    if not rows:
        print(f"{args.csv_path}: no rows", file=sys.stderr)
        return 1

    kn_pairs = sorted({(r["k"], r["n"]) for r in rows})
    depths   = sorted({r["depth"] for r in rows})
    models   = sorted({r["channel_model"] for r in rows})
    seeds    = sorted({r["seed"] for r in rows})

    print(f"=== fec_bench summary: {args.csv_path} ===")
    print(f"rows={len(rows)} "
          f"(k,n)={len(kn_pairs)} pairs "
          f"depths={depths} "
          f"models={models} "
          f"seeds={len(seeds)}")

    print_uniform(rows)
    print_ge(rows)
    print_periodic(rows)
    print_cpu_table(rows)
    print_latency_table(rows)
    print_memory_table(rows)
    print_burst_improvement(rows)
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
