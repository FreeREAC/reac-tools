# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Pau Aliagas <linuxnow@gmail.com>

"""Command-line entry: analyze a saved REAC tcpdump-text capture.

Usage:
    python3 -m reac.cli CAPTURE.txt [--vlan N] [--src MAC] [--expect-vlan N --expect-src MAC] [--fps F]

Groups frames by (src, vlan), reports loss/reorder/dup + jitter per stream,
and (when --expect-* given) flags cross-mix foreign frames.
"""
import argparse
import collections
import sys

from .parser import parse_tcpdump_text
from .analyzer import analyze_stream, jitter_stats, detect_crossmix


def main(argv=None):
    """CLI: analyze a saved tcpdump-text capture for loss/reorder/dup/jitter and cross-mix."""
    ap = argparse.ArgumentParser(description="Analyze a REAC tcpdump-text capture")
    ap.add_argument("capture", help="tcpdump -xx [-e] text file")
    ap.add_argument("--fps", type=float, default=3000.0,
                    help="nominal REAC frame rate for jitter (default 3000)")
    ap.add_argument("--expect-vlan", type=int, default=None)
    ap.add_argument("--expect-src", default=None)
    args = ap.parse_args(argv)

    text = open(args.capture, errors="replace").read()
    frames = parse_tcpdump_text(text)
    if not frames:
        print("no REAC frames parsed", file=sys.stderr)
        return 1

    nominal_dt = 1.0 / args.fps if args.fps else 0.000333
    groups = collections.defaultdict(list)
    for f in frames:
        groups[(f.src, f.vlan)].append(f)

    print(f"{len(frames)} frames, {len(groups)} stream(s)\n")
    for (src, vlan), fs in sorted(groups.items()):
        r = analyze_stream(fs)
        j = jitter_stats(fs, nominal_dt=nominal_dt)
        print(f"stream src={src} vlan={vlan}  n={len(fs)}")
        print(f"  loss={r.lost}  reorder={r.reordered}  dup={r.duplicated}")
        print(f"  mean_dt={j.mean_dt*1e6:.1f}us  max_gap={j.max_gap*1e6:.1f}us "
              f"({j.max_gap_ratio:.1f}x nominal)")
        if r.lost == 0 and j.max_gap_ratio < 3:
            print("  -> clean")
        elif j.max_gap_ratio >= 3:
            print("  -> JITTER BURST (can break REAC clock lock -> clicking)")
        if r.lost:
            print("  -> DATAGRAM LOSS")
        print()

    if args.expect_vlan is not None and args.expect_src:
        foreign = detect_crossmix(frames, expect_vlan=args.expect_vlan,
                                  expect_src=args.expect_src)
        print(f"cross-mix: {len(foreign)} foreign frame(s) "
              f"(expected vlan={args.expect_vlan} src={args.expect_src})")
        if foreign:
            print("  -> A/B ISOLATION LEAK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
