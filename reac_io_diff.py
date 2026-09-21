#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Pau Aliagas <linuxnow@gmail.com>
#
# reac_io_diff.py -- align a re-pacer's INPUT capture against its OUTPUT capture by
# AUDIO CONTENT (the counter is rewritten, so we can't align by counter) and report
# exactly what the re-pacer changed: which byte positions differ, how many output
# frames are PLC duplicates (audio == previous output), how many input frames were
# dropped (never appear in output), and how many output frames were synthesized
# (audio found nowhere in input). This is the literal "are we sending the mixer the
# same frames the box produced?" test.
#
# Usage: reac_io_diff.py <in.pcap> <out.pcap> <src_mac_hex> <frame_len>
#   e.g. reac_io_diff.py /tmp/si.pcap /tmp/so.pcap 0040abc40680 1204

import sys
import struct
from collections import Counter

HDR = 50  # audio starts here (14 eth + 2 cnt + 2 type + 32 desc)


def frames(path, src, ln):
    d = open(path, "rb").read()
    o, out = 24, []
    while o + 16 <= len(d):
        incl, orig = struct.unpack("<II", d[o + 8:o + 16])
        o += 16
        p = d[o:o + incl]
        o += incl
        if orig != ln or len(p) < ln:
            continue
        if p[6:12].hex() != src:
            continue
        out.append(p[:ln])
    return out


def main():
    fin, fout, src, ln = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4])
    ain = ln - HDR - 2                       # audio bytes (drop 2-byte trailer marker)
    IN = frames(fin, src, ln)
    OUT = frames(fout, src, ln)
    print(f"src={src} len={ln}  IN={len(IN)} frames  OUT={len(OUT)} frames  audio={ain}B")
    if not IN or not OUT:
        print("  (missing frames in one side)"); return 1

    # map input audio payload -> the full input frame (first occurrence wins)
    inmap = {}
    for p in IN:
        inmap.setdefault(bytes(p[HDR:HDR + ain]), p)

    matched = plc = synth = 0
    bytediff = Counter()           # byte-position -> count of frames where it differs
    prev_audio = None
    used = set()
    for p in OUT:
        a = bytes(p[HDR:HDR + ain])
        if a == prev_audio:
            plc += 1               # repeated audio = PLC conceal (or a real silent repeat)
        prev_audio = a
        ip = inmap.get(a)
        if ip is None:
            synth += 1
            continue
        matched += 1
        used.add(a)
        # diff every byte except the audio region we matched on
        for i in range(ln):
            if HDR <= i < HDR + ain:
                continue
            if p[i] != ip[i]:
                bytediff[i] += 1

    dropped = sum(1 for a in inmap if a not in used)
    print(f"  matched(audio found in input) = {matched}")
    print(f"  PLC repeats (audio == prev out) = {plc}   ({100*plc/max(1,len(OUT)):.2f}% of output)")
    print(f"  synthesized (audio NOT in input) = {synth}")
    print(f"  input frames never emitted (dropped) = {dropped}")
    print("  --- byte positions that DIFFER on matched frames (expect only 14,15 = counter) ---")
    if not bytediff:
        print("    NONE — output is byte-identical to input except the matched audio")
    else:
        for pos in sorted(bytediff):
            tag = " <-- counter" if pos in (14, 15) else (" <-- DESCRIPTOR/HEADER!!" if pos < HDR else " <-- TRAILER")
            print(f"    byte[{pos}]: differs in {bytediff[pos]} frames{tag}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
