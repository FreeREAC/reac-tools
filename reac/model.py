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

# Frame geometry. A clean REAC frame is FRAME_OVERHEAD + n * BYTES_PER_CHANNEL
# bytes on the wire, where n is the channel width -- 40 for the master's
# downstream broadcast (1492 B), the box's own input count upstream (S-1608 ->
# 628 B, S-0808 -> 340 B, S-4000 -> 1204 B). Strip the 14-byte Ethernet header
# and the same formula reads PAYLOAD_OVERHEAD + n * BYTES_PER_CHANNEL.
BYTES_PER_CHANNEL = 36              # 12 samples x 3 B, 24-bit
ETHERNET_HEADER = 14                # dst + src + ethertype, ahead of the payload
FRAME_OVERHEAD = 52                 # 50 B L2 header + 2 B C2 EA end marker
PAYLOAD_OVERHEAD = FRAME_OVERHEAD - ETHERNET_HEADER

# Some captures carry 2 extra bytes AFTER the C2 EA end marker. They are not a
# REAC field: they are the low 16 bits of the frame's own Ethernet FCS (crc32
# over the preceding bytes, little-endian), left in place by the capture path.
# Measured over the private capture corpus: the identity holds for 217,558 of
# 217,558 trailered frames, in both directions and across generations, and 22
# of 83 captures carry none at all -- the variable is the capture rig, not the
# gear. See libreac's reac_frame_clean_len(), of which this is the payload-side
# twin. Never model it as a protocol field.
FCS_RESIDUE = 2


def clean_payload_len(n):
    """Payload length with the FCS residue stripped, if it is there.

    A clean payload is PAYLOAD_OVERHEAD + width * BYTES_PER_CHANNEL bytes, so a
    length that is 2 past one of those carries the residue and comes back
    reduced by 2 (1480 -> 1478 downstream, 616 -> 614 from an S-1608). Every
    other length, including every clean one, is returned unchanged.
    """
    if (n >= PAYLOAD_OVERHEAD + FCS_RESIDUE
            and (n - PAYLOAD_OVERHEAD) % BYTES_PER_CHANNEL == FCS_RESIDUE):
        return n - FCS_RESIDUE
    return n

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
    payload:     the payload bytes, when the source had them. None when the
                 capture format only yielded framing (identity-based work, such
                 as mirror-twin dedup, needs the bytes and skips a frame
                 without them).
    """
    ts: float
    src: str
    vlan: Optional[int]
    seq: int
    payload_len: int
    payload: Optional[bytes] = None
