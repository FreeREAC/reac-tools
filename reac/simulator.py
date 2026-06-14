# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Pau Aliagas <linuxnow@gmail.com>

"""Generate synthetic REAC frame streams with injectable transport faults.

Used to validate the analyzer: inject a known fault, assert the analyzer
reports exactly it. No randomness by default so tests are deterministic.
"""
from .model import Frame, SEQ_MODULUS


def simulate_stream(
    n,
    src,
    vlan,
    seq0=0,
    nominal_dt=0.000333,
    payload_len=1478,
    t0=0.0,
    drop_indices=None,
    dup_indices=None,
    swap_indices=None,
    crossmix_indices=None,
    crossmix_src=None,
    crossmix_vlan=None,
    burst_at=None,
    burst_mult=1.0,
):
    """Build a list of Frames modelling one REAC stream.

    Faults (all by frame index into the clean stream):
      drop_indices:     frames removed (loss)
      dup_indices:      frames repeated once (duplication)
      swap_indices:     index i swapped with i+1 (reorder)
      crossmix_indices: foreign frames inserted after these indices,
                        using crossmix_src / crossmix_vlan
      burst_at/mult:    multiply the inter-arrival gap before this index
    """
    drop = set(drop_indices or [])
    dup = set(dup_indices or [])
    swap = set(swap_indices or [])
    crossmix = set(crossmix_indices or [])

    # 1. clean frames with wrapping seq and even timing
    frames = []
    for i in range(n):
        ts = t0 + i * nominal_dt
        if burst_at is not None and i >= burst_at:
            ts += nominal_dt * (burst_mult - 1.0)  # shift everything after the burst
        seq = (seq0 + i) % SEQ_MODULUS
        frames.append(Frame(ts=ts, src=src, vlan=vlan, seq=seq, payload_len=payload_len))

    # 2. reorder: swap adjacent pairs (keeps timestamps monotonic-ish per arrival)
    for i in sorted(swap):
        if 0 <= i < len(frames) - 1:
            frames[i], frames[i + 1] = frames[i + 1], frames[i]

    # 3. build output applying drop / dup / crossmix-insert by original index
    out = []
    for i, f in enumerate(frames):
        if i in drop:
            continue
        out.append(f)
        if i in dup:
            out.append(Frame(ts=f.ts, src=f.src, vlan=f.vlan, seq=f.seq,
                             payload_len=f.payload_len))
        if i in crossmix:
            out.append(Frame(ts=f.ts, src=crossmix_src, vlan=crossmix_vlan,
                             seq=f.seq, payload_len=f.payload_len))
    return out
