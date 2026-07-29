# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Pau Aliagas <linuxnow@gmail.com>

"""Characterize a REAC pcap — the on-rig decision-tree tool.

Given a capture, report:
  - the RATE fingerprint: packets/s -> nearest REAC rate (44.1 / 48 / 96 kHz),
    since REAC carries no rate field (rate = pps x 12 samples/packet);
  - frame size (payload length) distribution;
  - sequence health (loss / reorder / dup);
  - per-channel peak level -> active-channel count + saturation flag
    (how many slots actually carry signal, and it surfaces a gain/justification
    bug = many channels pinned near full-scale);
  - the frame-type histogram (the type[2] word: 0000 audio/filler, etc.).

Mirror twins are dropped first. A capture taken off a port mirror that spans
both RX and TX carries every frame twice; counted in, they double the pps and a
48 kHz console fingerprints as 96 kHz. The count is reported, not swallowed.

  python3 -m reac.characterize CAPTURE.pcap [...]

Frame layout (reacdriver REACPacketHeader + obs-h8819, verified at 48k):
  payload = counter[2] + type[2] + data[32] + audio[1440] + ending[2]
  audio   = 12 time-samples x 40 channel-slots x 3 bytes, even/odd interleave.
"""
import sys
from collections import Counter
from dataclasses import dataclass, field

from .analyzer import analyze_stream, dedupe_mirror_twins
from .model import Frame, RATE_PPS, rate_from_pps
from .pcap import read_pcap_raw

_AUDIO_OFF = 36                       # counter(2) + type(2) + data(32)
_N_CH = 40
_N_SAMP = 12
_RES = 3
_STRIDE = _N_CH * _RES                # 120 B between successive time-samples
_AUDIO_LEN = _N_SAMP * _N_CH * _RES   # 1440
_FULLSCALE = 0x7FFFFF
_RATES = RATE_PPS  # rate -> nominal pps (= rate / 12), defined in reac.model


@dataclass
class Report:
    n_frames: int = 0
    payload_lens: list = field(default_factory=list)
    pps: float = 0.0
    inferred_rate: int = 0
    loss: int = 0
    reordered: int = 0
    duplicated: int = 0
    n_channels: int = _N_CH
    channel_peak: list = field(default_factory=list)
    active_channels: int = 0
    saturated_channels: int = 0
    type_hist: dict = field(default_factory=dict)
    mirror_twins: int = 0     # duplicate copies dropped before anything was measured
    summary: str = ""


def _sample(audio, ch, s):
    """Signed 24-bit value of channel ch, time-sample s (obs-h8819 interleave)."""
    sp = (ch & ~1) * _RES + s * _STRIDE
    if sp + 6 > len(audio):
        return 0
    if ch & 1:
        b0, b1, b2 = audio[sp + 4], audio[sp + 5], audio[sp + 2]
    else:
        b0, b1, b2 = audio[sp + 3], audio[sp + 0], audio[sp + 1]
    v = b0 | (b1 << 8) | (b2 << 16)
    return v - 0x1000000 if v & 0x800000 else v


def characterize(path):
    raw_rows = read_pcap_raw(path)
    # A capture off a both-directions port mirror carries every frame twice.
    # Left in, the twins double the pps this reports -- 4000 reads as 8000, so
    # a 48 kHz console fingerprints as 96 kHz -- and count as sequence dups.
    rows = dedupe_mirror_twins(raw_rows, key=lambda row: (row[1], row[4]))
    r = Report(n_frames=len(rows), mirror_twins=len(raw_rows) - len(rows))
    if not rows:
        r.summary = "no REAC (0x8819) frames in %s" % path
        return r

    r.payload_lens = [len(p) for (_t, _s, _v, _q, p) in rows]
    ts = [t for (t, *_rest) in rows]
    span = ts[-1] - ts[0]
    r.pps = (len(rows) - 1) / span if span > 0 else 0.0
    r.inferred_rate = rate_from_pps(r.pps) or 0  # 0 = matches no REAC rate

    frames = [Frame(ts=t, src=s, vlan=v, seq=q, payload_len=len(p))
              for (t, s, v, q, p) in rows]
    sr = analyze_stream(frames)
    r.loss, r.reordered, r.duplicated = sr.lost, sr.reordered, sr.duplicated

    peak = [0] * _N_CH
    for (_t, _s, _v, _q, p) in rows:
        audio = p[_AUDIO_OFF:_AUDIO_OFF + _AUDIO_LEN]
        for ch in range(_N_CH):
            cpk = max(abs(_sample(audio, ch, s)) for s in range(_N_SAMP))
            if cpk > peak[ch]:
                peak[ch] = cpk
    r.channel_peak = peak
    r.active_channels = sum(1 for pk in peak if pk > 256)
    r.saturated_channels = sum(1 for pk in peak if pk >= _FULLSCALE - 0xFF)
    r.type_hist = dict(Counter(bytes(p[2:4]).hex() for (_t, _s, _v, _q, p) in rows))

    rate_lbl = "%g kHz" % (r.inferred_rate / 1000.0) if r.inferred_rate else "no REAC rate"
    twin_lbl = (" (+%d mirror twins dropped)" % r.mirror_twins) if r.mirror_twins else ""
    r.summary = ("%s (%.0f pps); %d frames%s; %s B; loss %d / reord %d / dup %d; "
                 "%d slots, %d active, %d saturated; types %s") % (
        rate_lbl, r.pps, r.n_frames, twin_lbl,
        "/".join(str(x) for x in sorted(set(r.payload_lens))),
        r.loss, r.reordered, r.duplicated,
        r.n_channels, r.active_channels, r.saturated_channels, r.type_hist)
    return r


def main(argv=None):
    argv = argv if argv is not None else sys.argv[1:]
    if not argv:
        print("usage: python3 -m reac.characterize CAPTURE.pcap [...]", file=sys.stderr)
        return 2
    for path in argv:
        r = characterize(path)
        print("%s: %s" % (path, r.summary))
    print("--- interpret (the rate is set BY pps alone: pps = rate / 12) ---")
    print("  pps ~3675  -> 44.1 kHz, 40 ch  => REAC_MODE_44K1 = {44100,40,12}")
    print("  pps ~4000  -> 48 kHz,   40 ch  => REAC_MODE_48K  = {48000,40,12}")
    print("  pps ~8000  -> 96 kHz,   40 ch  => REAC_MODE_96K  = {96000,40,12}")
    print("  the channel count is 40 at every rate: 96 kHz doubles the packet rate,")
    print("    it does NOT halve the channels (settled in libreac; the old")
    print("    {96000,20,24} channel-halving hypothesis is disproved). So a capture")
    print("    with ~20 active channels is a 20-channel signal count, not a rate clue.")
    print("  pps near none of the three -> the stream is off nominal: a box losing")
    print("    sample-clock lock streams slow. That is the fault, not a fourth rate.")
    print("  many channels saturated (peak ~0x7FFFFF) -> gain/24-bit-justification bug, not transport")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
