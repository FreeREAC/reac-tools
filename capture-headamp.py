#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Pau Aliagas <linuxnow@gmail.com>

"""Interactive REAC head-amp capture harness — marks one segment per toggle.

Tomorrow's grab: a real Roland master (M-200/M-480/M-5000) drives an S-0808 and
the operator toggles ONE head-amp control at a time (gain step, 48V, polarity)
on a named channel. This walks the operator through the exact plan, and for each
step captures a few seconds of STEADY STATE (after the control is set) into its
own pcap, so every segment is cleanly attributable to one control change. The
byte-diff analyzer (``python3 -m reac.headamp``) then diffs the segments.

Capture on a port that carries BOTH directions of the S-0808<->master link (a
switch SPAN/mirror, as the corpus mirror captures do): head-amp commands ride the
master's downstream heartbeat, the box's state its upstream return.

Pure stdlib; shells out to ``tcpdump`` (needs CAP_NET_RAW / root). busybox-safe:
we time the capture in Python and kill tcpdump, never relying on ``timeout``.

    sudo python3 capture-headamp.py --iface mirror0 --seconds 5 \
         --master M-200 --box S-0808 --outdir headamp-$(date +%F)
    # then:  python3 -m reac.headamp headamp-<date>/manifest.json
"""
import argparse
import datetime
import json
import os
import subprocess
import sys
import time

try:
    from reac.pcap import read_pcap            # frame count per segment
except Exception:                              # run standalone next to the reac/ pkg
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from reac.pcap import read_pcap


# The exact toggle sequence (mirrors S-0808-headamp-capture-procedure.md). One
# control at a time; gain swept in known dB steps so the law is derivable; CH2
# repeated so the channel-selector byte is confirmed. value is numeric dB for
# gain, "on"/"off" for 48V/polarity.
DEFAULT_PLAN = [
    dict(label="baseline (all flat, 48V off, polarity normal)", control="none",
         channel=None, value=None, unit=None,
         prompt="Leave EVERY input flat: 0 dB gain, 48V OFF, polarity NORMAL."),
    dict(label="CH1 gain +10dB", control="gain", channel=1, value=10, unit="dB",
         prompt="Set CH1 gain to +10 dB (relative to flat). Nothing else changed."),
    dict(label="CH1 gain +20dB", control="gain", channel=1, value=20, unit="dB",
         prompt="Set CH1 gain to +20 dB."),
    dict(label="CH1 gain +30dB", control="gain", channel=1, value=30, unit="dB",
         prompt="Set CH1 gain to +30 dB."),
    dict(label="CH1 gain +40dB", control="gain", channel=1, value=40, unit="dB",
         prompt="Set CH1 gain to +40 dB."),
    dict(label="CH1 gain back to flat", control="gain", channel=1, value=0, unit="dB",
         prompt="Return CH1 gain to 0 dB (flat)."),
    dict(label="CH1 48V ON", control="48v", channel=1, value="on", unit=None,
         prompt="Switch CH1 48V phantom ON. Gain flat, polarity normal."),
    dict(label="CH1 48V OFF", control="48v", channel=1, value="off", unit=None,
         prompt="Switch CH1 48V phantom OFF again."),
    dict(label="CH1 polarity INV", control="polarity", channel=1, value="on", unit=None,
         prompt="Switch CH1 polarity to INVERTED (phase flip). 48V off, gain flat."),
    dict(label="CH1 polarity NORMAL", control="polarity", channel=1, value="off", unit=None,
         prompt="Switch CH1 polarity back to NORMAL."),
    dict(label="CH2 gain +20dB", control="gain", channel=2, value=20, unit="dB",
         prompt="Set CH2 gain to +20 dB (confirms the channel-selector byte). CH1 flat."),
    dict(label="CH2 gain back to flat", control="gain", channel=2, value=0, unit="dB",
         prompt="Return CH2 gain to 0 dB (flat)."),
    dict(label="CH2 48V ON", control="48v", channel=2, value="on", unit=None,
         prompt="Switch CH2 48V phantom ON."),
    dict(label="CH2 48V OFF", control="48v", channel=2, value="off", unit=None,
         prompt="Switch CH2 48V phantom OFF."),
]


def capture_segment(iface, out_pcap, seconds, tcpdump, dry_run):
    """Capture `seconds` of 0x8819 traffic on `iface` into out_pcap. Return frame count."""
    if dry_run:
        # produce an empty but valid pcap so the manifest + pipeline can be exercised
        from reac.pcap import write_pcap
        write_pcap(out_pcap, [])
        return 0
    cmd = [tcpdump, "-i", iface, "-s", "0", "-w", out_pcap, "ether proto 0x8819"]
    p = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        time.sleep(seconds)
    finally:
        p.terminate()
        try:
            p.wait(timeout=5)
        except subprocess.TimeoutExpired:
            p.kill()
    try:
        return len(read_pcap(out_pcap))
    except Exception:
        return -1


def main(argv=None):
    ap = argparse.ArgumentParser(description="Interactive REAC head-amp capture harness")
    ap.add_argument("--iface", required=True, help="capture interface (SPAN/mirror carrying both dirs)")
    ap.add_argument("--outdir", default=None, help="output dir (default headamp-<UTC timestamp>)")
    ap.add_argument("--seconds", type=float, default=5.0, help="steady-state capture per step (default 5)")
    ap.add_argument("--master", default="?", help="master model label (M-200/M-480/M-5000)")
    ap.add_argument("--box", default="S-0808", help="stagebox model label")
    ap.add_argument("--plan", default=None, help="JSON step list overriding the default sequence")
    ap.add_argument("--tcpdump", default="tcpdump", help="tcpdump binary path")
    ap.add_argument("--dry-run", action="store_true", help="write empty pcaps (pipeline test, no capture)")
    args = ap.parse_args(argv)

    plan = DEFAULT_PLAN
    if args.plan:
        with open(args.plan) as f:
            plan = json.load(f)

    stamp = datetime.datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    outdir = args.outdir or ("headamp-%s" % stamp)
    os.makedirs(outdir, exist_ok=True)

    print("REAC head-amp capture — master=%s box=%s iface=%s -> %s/"
          % (args.master, args.box, args.iface, outdir))
    print("%d steps, %.1fs steady-state each. One control per step.\n" % (len(plan), args.seconds))

    segments = []
    for i, step in enumerate(plan):
        label = step["label"]
        pcap_name = "seg%02d-%s.pcap" % (i, step["control"])
        pcap_path = os.path.join(outdir, pcap_name)
        print("STEP %2d/%d  %s" % (i, len(plan) - 1, label))
        print("  %s" % step.get("prompt", ""))
        try:
            input("  >> set it, let it settle, then press Enter to capture %.1fs... " % args.seconds)
        except (EOFError, KeyboardInterrupt):
            print("\naborted at step %d; manifest not written." % i)
            return 1
        n = capture_segment(args.iface, pcap_path, args.seconds, args.tcpdump, args.dry_run)
        tag = "%d frames" % n if n >= 0 else "COUNT FAILED"
        if n == 0 and not args.dry_run:
            print("  !! captured 0 REAC frames — check the mirror/iface before continuing.")
        print("  -> %s (%s)\n" % (pcap_name, tag))
        segments.append(dict(index=i, label=label, control=step["control"],
                             channel=step.get("channel"), value=step.get("value"),
                             unit=step.get("unit"), pcap=pcap_name, seconds=args.seconds,
                             frames=n))

    manifest = dict(capture="headamp-%s" % stamp, created=stamp + "Z",
                    iface=args.iface, master=args.master, box=args.box,
                    seconds=args.seconds, segments=segments)
    mpath = os.path.join(outdir, "manifest.json")
    with open(mpath, "w") as f:
        json.dump(manifest, f, indent=1)
    print("wrote %s (%d segments)." % (mpath, len(segments)))
    print("analyze with:  python3 -m reac.headamp %s" % mpath)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
