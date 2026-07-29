# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Pau Aliagas <linuxnow@gmail.com>

"""Command-line entry: analyze a saved REAC tcpdump-text capture.

Usage:
    python3 -m reac.cli CAPTURE.txt [--rate HZ | --fps PPS]
                        [--expect-vlan N --expect-src MAC]

Groups frames by (src, vlan), reports loss/reorder/dup + jitter per stream,
and (when --expect-* given) flags cross-mix foreign frames.

The jitter ratio is measured against a nominal frame interval, so it is only
as good as the frame rate fed to it. REAC carries no rate field, so by default
each stream's rate is measured from its own median inter-arrival and snapped to
the nearest REAC rate (pps = rate / 12). A stream that matches none of them is
reported as unresolved rather than snapped: pass --rate (or --fps) to say what
the console was actually running.

Mirror twins are dropped before any of that. A capture taken off a port mirror
that spans both RX and TX sees each frame twice, so half the inter-arrivals are
near-zero and the median lands between the two modes -- on a real 48 kHz
S-1608 cold-connect the master reads 57.0 us (210 kHz) before the dedup and
250.1 us (48.0 kHz) after. Below 10 % tolerance that only ever produced RATE
UNRESOLVED, so no rate was ever invented; but no mirrored capture could be
measured at all either.

Exit status: 0 analyzed, 1 nothing to analyze, 3 at least one stream's rate
could not be resolved (its jitter ratio was withheld rather than guessed).
"""
import argparse
import collections
import statistics
import sys

from .parser import parse_tcpdump_text
from .analyzer import (analyze_stream, dedupe_mirror_twins, detect_crossmix,
                       jitter_stats)
from .model import (RATE_PPS, RATE_TOLERANCE, REAC_RATES, pps_for_rate,
                    rate_from_pps)


def modal_pps(frames):
    """Typical arrival rate of a stream in packets/s, 0.0 if not measurable.

    Taken from the median inter-arrival, not from count/span: the faults this
    tool looks for are stalls and loss gaps, and those drag a span-averaged
    rate below nominal. The median reports the spacing the stream actually
    holds between the faults, which is the interval a jitter ratio wants.
    """
    if len(frames) < 2:
        return 0.0
    deltas = [frames[i].ts - frames[i - 1].ts for i in range(1, len(frames))]
    mid = statistics.median(deltas)
    return 1.0 / mid if mid > 0 else 0.0


def resolve_nominal_pps(frames, forced_pps=None):
    """(nominal_pps, modal_pps, rate) for one stream.

    nominal_pps is None when nothing trustworthy can be established: no forced
    value was given and the measured rate matches no REAC rate. Callers must
    then refuse to report a jitter ratio rather than invent one.
    """
    pps = modal_pps(frames)
    if forced_pps is not None:
        return forced_pps, pps, None
    rate = rate_from_pps(pps)
    if rate is None:
        return None, pps, None
    return pps_for_rate(rate), pps, rate


def _rates_help():
    return ", ".join("%d->%g" % (r, RATE_PPS[r]) for r in sorted(REAC_RATES))


def main(argv=None):
    """CLI: analyze a saved tcpdump-text capture for loss/reorder/dup/jitter and cross-mix."""
    ap = argparse.ArgumentParser(description="Analyze a REAC tcpdump-text capture")
    ap.add_argument("capture", help="tcpdump -xx [-e] text file")
    rate_opt = ap.add_mutually_exclusive_group()
    rate_opt.add_argument("--rate", type=int, choices=sorted(REAC_RATES), default=None,
                          help="console sample rate in Hz; the nominal frame rate "
                               "is derived as rate/12 pps (%s)" % _rates_help())
    rate_opt.add_argument("--fps", type=float, default=None,
                          help="nominal frame rate in packets/s, overriding --rate. "
                               "Default: measured per stream from the capture and "
                               "snapped to the nearest REAC rate")
    ap.add_argument("--expect-vlan", type=int, default=None)
    ap.add_argument("--expect-src", default=None)
    args = ap.parse_args(argv)

    if args.fps is not None and args.fps <= 0:
        ap.error("--fps must be positive")

    forced_pps = args.fps if args.fps is not None else (
        pps_for_rate(args.rate) if args.rate is not None else None)
    forced_note = ("--fps" if args.fps is not None else
                   "--rate %d" % args.rate if args.rate is not None else None)

    with open(args.capture, errors="replace") as fh:
        text = fh.read()
    frames = parse_tcpdump_text(text)
    if not frames:
        print("no REAC frames parsed", file=sys.stderr)
        return 1

    groups = collections.defaultdict(list)
    for f in frames:
        groups[(f.src, f.vlan)].append(f)

    unresolved = 0
    print(f"{len(frames)} frames, {len(groups)} stream(s)\n")
    for (src, vlan), raw_fs in sorted(groups.items()):
        # Before anything is measured: a capture taken off a both-directions
        # port mirror carries every frame twice, and half its inter-arrivals
        # are then near-zero. Nothing below -- rate, jitter, loss -- means what
        # it says until the twins are gone.
        fs = dedupe_mirror_twins(raw_fs)
        twins = len(raw_fs) - len(fs)
        r = analyze_stream(fs)
        print(f"stream src={src} vlan={vlan}  n={len(fs)}")
        if twins:
            print(f"  mirror twins dropped: {twins} of {len(raw_fs)} "
                  f"-- capture is off a both-directions port mirror")
        print(f"  loss={r.lost}  reorder={r.reordered}  dup={r.duplicated}")

        nominal_pps, pps, rate = resolve_nominal_pps(fs, forced_pps)
        if nominal_pps is None:
            unresolved += 1
            if len(fs) < 2:
                print("  rate: not measurable from a single frame "
                      "-- pass --rate or --fps")
            else:
                print(f"  rate: modal {pps:.0f} pps matches no REAC rate "
                      f"({_rates_help()})")
                print("  -> RATE UNRESOLVED: the stream is off nominal (a box losing "
                      "clock lock")
                print("     streams slow). Jitter ratio withheld; pass --rate or "
                      "--fps to force one.")
        else:
            if forced_note:
                print(f"  rate: nominal {nominal_pps:.0f} pps ({forced_note}), "
                      f"modal {pps:.0f} pps")
                if pps and abs(pps - nominal_pps) > RATE_TOLERANCE * nominal_pps:
                    seen = rate_from_pps(pps)
                    hint = " = %g kHz" % (seen / 1000.0) if seen else ""
                    print(f"  -> WARNING: the forced nominal disagrees with the "
                          f"stream, which runs at {pps:.0f} pps{hint};")
                    print("     every ratio below is scaled by that mismatch")
            else:
                print(f"  rate: {rate / 1000:g} kHz -> nominal {nominal_pps:.0f} pps "
                      f"(inferred), modal {pps:.0f} pps")

        if len(fs) >= 2:
            j = jitter_stats(fs, nominal_dt=1.0 / nominal_pps if nominal_pps else 0.0)
            line = f"  mean_dt={j.mean_dt*1e6:.1f}us  max_gap={j.max_gap*1e6:.1f}us"
            if nominal_pps:
                line += f" ({j.max_gap_ratio:.1f}x nominal)"
            print(line)
            if nominal_pps:
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

    return 3 if unresolved else 0


if __name__ == "__main__":
    raise SystemExit(main())
