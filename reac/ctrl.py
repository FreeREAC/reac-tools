# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Pau Aliagas <linuxnow@gmail.com>

"""REAC control-plane parser (Python port of reac-pw's ``reac_ctrl.[ch]``).

The reac-pw C parser works on the FULL ethernet frame: the 32-byte control block
is ``frame[18:50]`` and the checksum is ``frame[49]`` such that
``Sum(frame[18..49]) mod 256 == 0``. This module works on the REAC **payload**
(what :func:`reac.pcap.read_pcap_raw` yields — the bytes after the ``0x8819``
ethertype), where the same block is ``payload[4:36]`` and the checksum is
``payload[35]``. The classification mirrors ``enum reac_ctrl_kind`` byte-for-byte.

On top of the C parser this adds the **per-channel head-amp table** decode: the
established-heartbeat (``cdea 01 03 0019``) block carries, after its 5-byte
header, a run of 3-byte channel entries ``<chan_id> <flag> <value>`` terminated
by ``00 00``. The ``value`` byte is ``0x00`` across the whole existing corpus —
it is the head-amp gain field the FSM evidence flags as unmapped (task #155),
and the ``flag`` byte is where 48V-phantom / polarity bits are expected. The
byte-diff analyzer (:mod:`reac.headamp`) diffs these entries across marked
capture segments to map gain / 48V / polarity.
"""
from dataclasses import dataclass, field

# Control block position within the REAC payload (payload = frame[14:]).
BLOCK_OFF = 4        # payload[4]  == frame[18]
BLOCK_END = 36       # payload[36] == frame[50] (one past end; = audio offset)
CKSUM_OFF = 35       # payload[35] == frame[49] (checksum, last block byte)
BLOCK_LEN = BLOCK_END - BLOCK_OFF   # 32

# reac_ctrl_kind (mirrors the C enum names).
NONE = "none"
FILLER = "filler"
PROBE = "probe"
MASTER_HB = "master_hb"
MASTER_ANNOUNCE = "master_announce"
GRANT = "grant"
BOX_HB = "box_hb"
UNKNOWN_CTRL = "unknown_ctrl"


@dataclass
class ChanEntry:
    """One 3-byte per-channel head-amp entry ``<chan_id> <flag> <value>``.

    off is the entry's ``chan_id`` offset WITHIN the payload (so callers can name
    the exact byte that a diff moved). value is the candidate gain byte; flag is
    the byte carrying the (candidate) 48V / polarity bits.
    """
    index: int          # entry ordinal (0-based)
    off: int            # payload offset of chan_id (flag=off+1, value=off+2)
    chan_id: int
    flag: int
    value: int


@dataclass
class Ctrl:
    """Parsed REAC control frame (payload view)."""
    kind: str = NONE
    type_word: int = 0          # payload[2:4] big-endian (0x0000 filler, 0xcdea, 0xcfea)
    op0: int = 0                # payload[4]  == frame[18]
    op1: int = 0                # payload[5]  == frame[19]
    op_len: int = 0             # payload[6:8] big-endian == frame[20:22]
    sel: int = 0                # payload[8]  == frame[22]
    block: bytes = b""          # the 32-byte control block payload[4:36]
    cksum_ok: bool = False      # Sum(block) mod 256 == 0
    entries: list = field(default_factory=list)   # list[ChanEntry] (heartbeat only)


def checksum_ok(payload):
    """True when Sum(payload[4:36]) mod 256 == 0 (the cdea/cfea block checksum).

    FILLER (type 0x0000) is checksum-exempt on the wire, so this is only
    meaningful for cdea/cfea control frames.
    """
    if len(payload) < BLOCK_END:
        return False
    return sum(payload[BLOCK_OFF:BLOCK_END]) & 0xFF == 0


def _decode_entries(block):
    """Decode the ``cdea 01 03`` per-channel head-amp table from a 32-byte block.

    Layout (ground-truthed against the corpus): a 5-byte header
    ``op0 op1 len_hi len_lo sel``, then EIGHT fixed 3-byte slots
    ``<chan_id> <flag> <value>`` (offsets 5,8,..,26), then a 2-byte trailer and
    the checksum byte. A slot with ``flag == 0`` is a separator/pad (e.g. the
    ``fe 00 00`` section marker), not a channel; slots with a non-zero flag
    (``0x28`` / ``0x38`` observed) are real head-amp entries — ``value`` is the
    candidate gain byte, ``flag`` the candidate 48V / polarity carrier. Returned
    entries keep their slot ordinal so a byte diff maps back to an exact slot.
    """
    entries = []
    slot = 0
    i = 5                                       # after op0,op1,len(2),sel
    while i + 3 <= BLOCK_LEN - 3:               # 8 slots: i in {5,8,...,26}
        chan_id, flag, value = block[i], block[i + 1], block[i + 2]
        if flag != 0x00:                        # flag==0 => separator/pad slot
            entries.append(ChanEntry(index=slot, off=BLOCK_OFF + i,
                                     chan_id=chan_id, flag=flag, value=value))
        slot += 1
        i += 3
    return entries


def parse(payload):
    """Classify a REAC payload's control block; return a :class:`Ctrl`.

    payload is the bytes after the ``0x8819`` ethertype (as read_pcap_raw gives).
    Returns kind=NONE when the payload is too short to hold a control block.
    """
    out = Ctrl()
    if len(payload) < BLOCK_END:
        return out
    out.type_word = (payload[2] << 8) | payload[3]
    out.op0 = payload[4]
    out.op1 = payload[5]
    out.op_len = (payload[6] << 8) | payload[7]
    out.sel = payload[8]
    out.block = bytes(payload[BLOCK_OFF:BLOCK_END])
    out.cksum_ok = checksum_ok(payload)

    t0, t1 = payload[2], payload[3]
    if t0 == 0x00 and t1 == 0x00:
        out.kind = FILLER
    elif t0 == 0xCF and t1 == 0xEA:
        out.kind = MASTER_ANNOUNCE
    elif t0 == 0xCD and t1 == 0xEA:
        if out.op0 == 0x04 and out.op1 == 0x03:
            out.kind = GRANT
        elif out.op0 == 0x01 and out.op1 == 0x03 and out.op_len == 0x0019:
            out.kind = MASTER_HB
            out.entries = _decode_entries(out.block)
        elif out.op0 == 0x01 and out.op1 == 0x03 and out.op_len == 0x0001:
            out.kind = BOX_HB
        elif out.op0 == 0x01:
            out.kind = PROBE
        else:
            out.kind = UNKNOWN_CTRL
    else:
        out.kind = UNKNOWN_CTRL
    return out


def signature(ctrl):
    """A stable key grouping frames that carry the SAME control layout.

    Diffing is only meaningful within one signature: (kind, op0, op1, op_len,
    sel). A head-amp toggle changes bytes WITHIN a signature's block, never the
    signature itself.
    """
    return (ctrl.kind, ctrl.op0, ctrl.op1, ctrl.op_len, ctrl.sel)
