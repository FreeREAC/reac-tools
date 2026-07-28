# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Pau Aliagas <linuxnow@gmail.com>

"""Core data types and framing constants for REAC stream analysis."""
from dataclasses import dataclass
from typing import Optional

# REAC sequence counter is a 16-bit field; it wraps at this modulus.
SEQ_MODULUS = 1 << 16

# A REAC frame carries this many time-samples per channel slot, at every rate.
# There is no rate field on the wire, so the packet rate *is* the sample rate
# divided by this: pps = rate / 12.
SAMPLES_PER_FRAME = 12

# The sample rates REAC runs at. 96 kHz doubles the packet rate and keeps all
# 40 channel slots (settled in libreac as REAC_MODE_96K); it does not halve
# the channel count.
REAC_RATES = (44100, 48000, 96000)

# How far a measured pps may sit from a nominal one and still be read as that
# rate, as a fraction of the nominal. 10 % absorbs short or jittery captures
# while still refusing a stream running well off nominal.
RATE_TOLERANCE = 0.10


def pps_for_rate(rate):
    """Nominal REAC packets/s for a sample rate: rate / 12."""
    return rate / SAMPLES_PER_FRAME


# rate -> nominal pps. The one rate table in the project; everything else
# derives from it: {44100: 3675, 48000: 4000, 96000: 8000}.
RATE_PPS = {rate: pps_for_rate(rate) for rate in REAC_RATES}


def rate_from_pps(pps, tolerance=RATE_TOLERANCE):
    """Nearest REAC sample rate to a measured pps, or None if none is near.

    Returning None rather than the nearest rate is the point. A stream measured
    well away from every nominal pps is a fault symptom -- a box that has lost
    sample-clock lock streams below nominal -- not an undiscovered fourth rate,
    and snapping it to a rate would launder the symptom into a framing figure.
    """
    if not pps or pps <= 0:
        return None
    rate = min(RATE_PPS, key=lambda r: abs(pps - RATE_PPS[r]))
    return rate if abs(pps - RATE_PPS[rate]) <= tolerance * RATE_PPS[rate] else None


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
