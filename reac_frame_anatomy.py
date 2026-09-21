#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Pau Aliagas <linuxnow@gmail.com>
#
# reac_frame_anatomy.py -- characterize REAC frames straight off a raw capture,
# making NO assumption about VLAN tagging or ethertype offset. For each frame it
# locates the 0x8819 REAC ethertype (untagged @12, one tag @16, QinQ @20), then
# decodes the header (counter, type, 32-byte descriptor) and classifies the frame
# as audio (type 16-17 == 0000) or control (cdea channel-map / cfea announce).
#
# Reports, per direction (split by source MAC + frame length):
#   * frame-length histogram + inferred channel count  ((len-hdr-marker)/3/12)
#   * ethertype offset histogram (is the stream VLAN-tagged?)
#   * control-frame inventory: type bytes, counts, cadence (gap in counter slots)
#   * counter monotonicity (clean +1, or gaps/dups -- the re-pacer's signature)
#   * sample header hexdumps for audio + each control type
#
# Usage: reac_frame_anatomy.py <pcap>

import sys
import struct
from collections import Counter, defaultdict


def frames(path):
    data = open(path, "rb").read()
    magic = struct.unpack("<I", data[:4])[0]
    end = "<" if magic in (0xA1B2C3D4, 0xA1B23C4D) else ">"
    nano = magic in (0xA1B23C4D, 0x4DC3B2A1)
    off = 24
    while off + 16 <= len(data):
        ts_s, ts_u, incl, orig = struct.unpack(end + "IIII", data[off:off + 16])
        off += 16
        pkt = data[off:off + incl]
        off += incl
        if len(pkt) >= 14:
            yield pkt, orig


def reac_off(pkt):
    """Return the byte offset of the 0x8819 ethertype, or -1. Scans the common
    tag depths so a VLAN/QinQ tag doesn't hide the REAC ethertype."""
    for e in (12, 16, 20):
        if len(pkt) > e + 1 and pkt[e] == 0x88 and pkt[e + 1] == 0x19:
            return e
    return -1


def hexs(b):
    return " ".join(f"{x:02x}" for x in b)


def main():
    if len(sys.argv) < 2:
        print("usage: reac_frame_anatomy.py <pcap>", file=sys.stderr)
        return 2
    path = sys.argv[1]

    total = 0
    reac = 0
    off_hist = Counter()
    # group by (src_mac, payload_len) == a direction/stream
    by_stream = defaultdict(lambda: {
        "n": 0, "lens": Counter(), "ctrl_types": Counter(),
        "counters": [], "ctrl_slots": [], "ctrl_idx": [], "ctrl_idx_t": {},
        "sample_audio": None, "sample_ctrl": {}, "dst": None, "eoff": Counter(),
    })

    for pkt, orig in frames(path):
        total += 1
        e = reac_off(pkt)
        off_hist[e] += 1
        if e < 0:
            continue
        reac += 1
        dst = bytes(pkt[0:6])
        src = bytes(pkt[6:12])
        # REAC header relative to the ethertype position e:
        #   e+2..e+3 = counter (LE16), e+4..e+5 = type, e+6..e+37 = 32B descriptor
        cnt = pkt[e + 2] | (pkt[e + 3] << 8) if len(pkt) > e + 3 else -1
        typ = bytes(pkt[e + 4:e + 6]) if len(pkt) > e + 5 else b""
        is_ctrl = typ != b"\x00\x00"
        key = (src.hex(), orig)
        st = by_stream[key]
        st["n"] += 1
        st["lens"][orig] += 1
        st["dst"] = dst.hex()
        st["eoff"][e] += 1
        st["counters"].append(cnt)
        hdr = bytes(pkt[max(0, e - 2):e + 38])
        if is_ctrl:
            st["ctrl_types"][typ.hex()] += 1
            st["ctrl_slots"].append(cnt)
            st["ctrl_idx"].append(st["n"])          # frame position (per stream)
            st["ctrl_idx_t"].setdefault(typ.hex(), []).append(st["n"])
            if typ.hex() not in st["sample_ctrl"]:
                st["sample_ctrl"][typ.hex()] = hexs(hdr)
        elif st["sample_audio"] is None:
            st["sample_audio"] = hexs(hdr)

    print(f"total frames={total}  REAC frames={reac}")
    print(f"ethertype offset histogram (12=untagged 16=1 VLAN 20=QinQ -1=non-REAC): "
          f"{dict(off_hist)}")
    print()

    for (src, ln), st in sorted(by_stream.items(), key=lambda kv: -kv[1]["n"]):
        # channel count, tag-aware: header before audio = e (mac+tags) + 2 ethertype
        # + 2 counter + 2 type + 32 descriptor; +2 trailing marker.
        e_dom = st["eoff"].most_common(1)[0][0] if st["eoff"] else 12
        tag = "tagged" if e_dom > 12 else "untagged"
        approx_ch = round((ln - e_dom - 38 - 2) / 3 / 12, 2) if ln > 60 else 0
        print(f"=== stream src={src} len={ln}B  frames={st['n']} "
              f"dst={st['dst']}  ~ch={approx_ch} ({tag}) ===")
        print(f"  length histogram: {dict(st['lens'])}")
        # control inventory + the headline metric: frames between control frames
        if st["ctrl_types"]:
            print(f"  CONTROL frame types: {dict(st['ctrl_types'])}")
            for t in sorted(st["ctrl_idx_t"]):                     # cadence PER control type
                ci = st["ctrl_idx_t"][t]
                per = st["n"] / max(1, len(ci))
                line = f"  {t}: {len(ci)} in {st['n']} -> 1 per {per:.0f} frames"
                if len(ci) >= 2:
                    fg = [b - a for a, b in zip(ci, ci[1:])]
                    mean = sum(fg) / len(fg)
                    std = (sum((g - mean) ** 2 for g in fg) / len(fg)) ** 0.5
                    reg = "REGULAR" if std < max(1.0, 0.05 * mean) else "irregular"
                    line += f"  | between: min={min(fg)} max={max(fg)} mean={mean:.0f} std={std:.0f} ({reg})"
                print(line)
        else:
            print("  CONTROL frames: none")
        # counter health
        cs = st["counters"]
        if len(cs) > 2:
            d = [(b - a) & 0xFFFF for a, b in zip(cs, cs[1:])]
            dc = Counter(d)
            print(f"  counter step histogram (1=clean): {dict(dc.most_common(6))}")
        if st["sample_audio"]:
            print(f"  audio  hdr[{'-2..+37'}]: {st['sample_audio']}")
        for t, h in st["sample_ctrl"].items():
            print(f"  ctrl {t} hdr: {h}")
        print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
