# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Pau Aliagas <linuxnow@gmail.com>

"""Core data types for REAC stream analysis."""
from dataclasses import dataclass
from typing import Optional

# REAC sequence counter is a 16-bit field; it wraps at this modulus.
SEQ_MODULUS = 1 << 16


@dataclass
class Frame:
    """A single captured REAC (EtherType 0x8819) frame.

    ts:          capture timestamp, seconds (float)
    src:         source MAC, lowercase colon-separated
    vlan:        802.1Q VLAN id the frame was seen on, or None if untagged
    seq:         16-bit REAC sequence counter (first 2 payload bytes, little-endian)
    payload_len: REAC payload length in bytes (after the 0x8819 ethertype)
    """
    ts: float
    src: str
    vlan: Optional[int]
    seq: int
    payload_len: int
