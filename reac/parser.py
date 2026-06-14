# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Pau Aliagas <linuxnow@gmail.com>

"""Parse tcpdump text captures of REAC (0x8819) traffic into Frame objects.

Handles two real-world formats from the rig:
  * full ethernet (`tcpdump -e -xx`): hex begins with the L2 header, so we
    locate the 0x8819 ethertype and take the REAC payload after it.
  * payload-only (`tcpdump -xx` after link strip): hex IS the REAC payload.

The REAC 16-bit sequence counter is the first 2 payload bytes, little-endian.
"""
import re

from .model import Frame

_HDR = re.compile(
    r"(?P<ts>\d\d:\d\d:\d\d\.\d+)\s+"
    r"(?P<src>[0-9a-f:]{17})\s+>\s+(?P<dst>[0-9a-f:]{17})"
    r".*?length (?P<len>\d+)"
)
_VLAN = re.compile(r"vlan (\d+)")
_HEX = re.compile(r"^\s*0x[0-9a-f]+:\s+(?P<body>[0-9a-f ]+?)(?:\s{2,}|$)")


def _to_seconds(ts):
    h, m, s = ts.split(":")
    return int(h) * 3600 + int(m) * 60 + float(s)


def _hexbytes(line):
    m = _HEX.match(line)
    if not m:
        return ""
    return re.sub(r"[^0-9a-f]", "", m.group("body"))


def _payload_after_8819(raw):
    b = bytes.fromhex(raw if len(raw) % 2 == 0 else raw[:-1])
    i = b.find(b"\x88\x19")
    return b[i + 2:] if i >= 0 else b  # payload-only dump: 8819 absent


def parse_tcpdump_text(text):
    """Parse tcpdump -xx (optionally -e) text into a list of Frames in order."""
    frames = []
    hdr = None
    hexparts = []

    def flush():
        if hdr is None or not hexparts:
            return
        payload = _payload_after_8819("".join(hexparts))
        seq = int.from_bytes(payload[0:2], "little") if len(payload) >= 2 else 0
        frames.append(Frame(
            ts=_to_seconds(hdr["ts"]),
            src=hdr["src"],
            vlan=int(hdr["vlan"]) if hdr["vlan"] else None,
            seq=seq,
            payload_len=int(hdr["len"]),
        ))

    for line in text.splitlines():
        mh = _HDR.search(line)
        if mh and not line.lstrip().startswith("0x"):
            flush()
            hdr = mh.groupdict()
            mv = _VLAN.search(line)
            hdr["vlan"] = mv.group(1) if mv else None
            hexparts = []
        elif hdr is not None:
            hx = _hexbytes(line)
            if hx:
                hexparts.append(hx)
    flush()
    return frames
