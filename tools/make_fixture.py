#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Pau Aliagas <linuxnow@gmail.com>

"""Regenerate tests/fixtures/real_reac_stream.pcap from the real capture payloads.

The on-site capture (tools/real_capture_payloads.json) was taken with
`tcpdump -x` (payload-only), so the L2 header was stripped. We reconstruct the
full Ethernet frame the wire actually carried: dst (broadcast) + src + 0x8819 +
the real REAC payload. The wire was untagged (proven on-site via raw hex byte
12-13), so no 802.1Q tag is added.

Run from the repo root:  python3 tools/make_fixture.py
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from reac.pcap import write_pcap  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, "real_capture_payloads.json")
OUT = os.path.join(HERE, "..", "tests", "fixtures", "real_reac_stream.pcap")


def _mac(s):
    return bytes.fromhex(s.replace(":", ""))


def _ts(s):
    h, m, sec = s.split(":")
    return int(h) * 3600 + int(m) * 60 + float(sec)


def build():
    """Rebuild the .pcap fixture from the recorded payloads; return the frame count."""
    rows = json.load(open(SRC))
    packets = []
    for r in rows:
        eth = _mac(r["dst"]) + _mac(r["src"]) + b"\x88\x19" + bytes.fromhex(r["payload"])
        packets.append((_ts(r["ts"]), eth))
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    write_pcap(OUT, packets)
    return len(packets)


if __name__ == "__main__":
    n = build()
    print(f"wrote {n} frames -> {os.path.relpath(OUT)}")
