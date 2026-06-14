# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Pau Aliagas <linuxnow@gmail.com>

"""Analyze a REAC frame stream for transport faults."""
from dataclasses import dataclass

from .model import SEQ_MODULUS

_HALF = SEQ_MODULUS // 2


def _signed_delta(cur, prev):
    """Shortest signed distance cur-prev on a 16-bit wrapping counter.

    Forward (small positive) = normal advance / loss gap.
    Negative = a late (reordered) frame.
    """
    return ((cur - prev + _HALF) % SEQ_MODULUS) - _HALF


@dataclass
class StreamReport:
    """Transport-fault counts for one REAC stream: lost / reordered / duplicated frames."""

    lost: int = 0
    reordered: int = 0
    duplicated: int = 0


def analyze_stream(frames):
    """Analyze a single REAC stream (frames in capture/arrival order).

    Unwraps the 16-bit sequence counter into a monotonic-ish extended space
    so that wrap-around and reordering don't masquerade as loss.
    """
    if not frames:
        return StreamReport()

    extended = []  # unwrapped seq per frame, in arrival order
    prev16 = frames[0].seq
    ext = frames[0].seq
    extended.append(ext)
    for f in frames[1:]:
        ext += _signed_delta(f.seq, prev16)
        prev16 = f.seq
        extended.append(ext)

    distinct = set(extended)
    duplicated = len(extended) - len(distinct)
    lost = (max(distinct) - min(distinct) + 1) - len(distinct)
    reordered = sum(
        1 for i in range(1, len(extended)) if extended[i] < extended[i - 1]
    )
    return StreamReport(lost=lost, reordered=reordered, duplicated=duplicated)


@dataclass
class JitterStats:
    """Inter-arrival timing for one stream: mean dt, worst gap, and gap/nominal ratio."""

    mean_dt: float = 0.0
    max_gap: float = 0.0
    max_gap_ratio: float = 0.0  # worst inter-arrival gap / nominal_dt


def jitter_stats(frames, nominal_dt):
    """Inter-arrival timing stats for a stream.

    nominal_dt is the expected frame interval (1/framerate). max_gap_ratio is
    the worst observed inter-arrival expressed as a multiple of nominal_dt; a
    ratio well above 1.0 means a burst that can break REAC clock lock.
    """
    if len(frames) < 2:
        return JitterStats()
    deltas = [frames[i].ts - frames[i - 1].ts for i in range(1, len(frames))]
    mean_dt = sum(deltas) / len(deltas)
    max_gap = max(deltas)
    return JitterStats(
        mean_dt=mean_dt,
        max_gap=max_gap,
        max_gap_ratio=max_gap / nominal_dt if nominal_dt else 0.0,
    )


def detect_crossmix(frames, expect_vlan, expect_src):
    """Return frames that don't belong to the expected single REAC stream.

    A foreign frame is one whose VLAN or source MAC differs from the stream
    that should be the sole occupant of this capture point. Any result means
    A/B isolation is leaking (the box would decode the other stream -> clicking).
    """
    return [
        f for f in frames
        if f.vlan != expect_vlan or f.src != expect_src
    ]
