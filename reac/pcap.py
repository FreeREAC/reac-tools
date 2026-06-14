# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Pau Aliagas <linuxnow@gmail.com>

"""Minimal classic pcap (libpcap) reader/writer for REAC Ethernet captures.

No dependencies. Classic .pcap only (not pcapng). Link-type 1 = Ethernet.
Reads frames whose EtherType is 0x8819 (REAC) into Frame objects; the seq is
the first 2 bytes of the REAC payload, little-endian.
"""
import struct

from .model import Frame

_GLOBAL = struct.Struct("<IHHiIII")   # magic, vmaj, vmin, tz, sigfigs, snaplen, network
_PKT = struct.Struct("<IIII")         # ts_sec, ts_usec, incl_len, orig_len
_MAGIC = 0xA1B2C3D4
_LINKTYPE_ETHERNET = 1
_REAC_ETHERTYPE = b"\x88\x19"


def write_pcap(path, packets):
    """Write (ts_float, raw_ethernet_bytes) tuples to a classic pcap file."""
    with open(path, "wb") as f:
        f.write(_GLOBAL.pack(_MAGIC, 2, 4, 0, 0, 65535, _LINKTYPE_ETHERNET))
        for ts, raw in packets:
            sec = int(ts)
            usec = int(round((ts - sec) * 1_000_000))
            f.write(_PKT.pack(sec, usec, len(raw), len(raw)))
            f.write(raw)


def _mac(b):
    return ":".join("%02x" % x for x in b)


def _vlan_and_payload(raw):
    """Return (vlan, reac_payload) from a raw ethernet frame, or (None, None)."""
    if len(raw) < 14:
        return None, None
    et = raw[12:14]
    if et == b"\x81\x00":              # 802.1Q tag
        vlan = int.from_bytes(raw[14:16], "big") & 0x0FFF
        inner = raw[16:18]
        if inner != _REAC_ETHERTYPE:
            return None, None
        return vlan, raw[18:]
    if et == _REAC_ETHERTYPE:
        return None, raw[14:]
    return None, None


def read_pcap(path):
    """Read a classic pcap file, returning REAC (0x8819) frames in order."""
    frames = []
    with open(path, "rb") as f:
        hdr = f.read(_GLOBAL.size)
        if len(hdr) < _GLOBAL.size:
            return frames
        magic = struct.unpack("<I", hdr[:4])[0]
        endian = "<" if magic == _MAGIC else ">"
        pkt = struct.Struct(endian + "IIII")
        while True:
            ph = f.read(pkt.size)
            if len(ph) < pkt.size:
                break
            sec, usec, incl, _orig = pkt.unpack(ph)
            raw = f.read(incl)
            if len(raw) < incl:
                break
            vlan, payload = _vlan_and_payload(raw)
            if payload is None:
                continue
            seq = int.from_bytes(payload[0:2], "little") if len(payload) >= 2 else 0
            frames.append(Frame(
                ts=sec + usec / 1_000_000,
                src=_mac(raw[6:12]),
                vlan=vlan,
                seq=seq,
                payload_len=len(payload),
            ))
    return frames


def read_pcap_raw(path):
    """Like read_pcap, but also keep the REAC payload bytes per frame.

    Returns a list of (ts, src, vlan, seq, payload_bytes) — needed for
    per-channel audio analysis (the framing-only read_pcap discards the audio).
    """
    out = []
    with open(path, "rb") as f:
        hdr = f.read(_GLOBAL.size)
        if len(hdr) < _GLOBAL.size:
            return out
        magic = struct.unpack("<I", hdr[:4])[0]
        endian = "<" if magic == _MAGIC else ">"
        pkt = struct.Struct(endian + "IIII")
        while True:
            ph = f.read(pkt.size)
            if len(ph) < pkt.size:
                break
            sec, usec, incl, _orig = pkt.unpack(ph)
            raw = f.read(incl)
            if len(raw) < incl:
                break
            vlan, payload = _vlan_and_payload(raw)
            if payload is None:
                continue
            seq = int.from_bytes(payload[0:2], "little") if len(payload) >= 2 else 0
            out.append((sec + usec / 1_000_000, _mac(raw[6:12]), vlan, seq, payload))
    return out
