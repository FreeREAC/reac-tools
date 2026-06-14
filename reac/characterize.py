# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Pau Aliagas <linuxnow@gmail.com>

"""Characterize a REAC pcap — the on-rig decision-tree tool.

Given a capture, report:
  - the RATE fingerprint: packets/s -> nearest REAC rate (44.1 / 48 / 96 kHz),
    since REAC carries no rate field (rate = pps x 12 samples/packet);
  - frame size (payload length) distribution;
  - sequence health (loss / reorder / dup);
  - per-channel peak level -> active-channel count + saturation flag
    (disambiguates 96k double-pps [40 active] vs channel-halving [20 active],
    and surfaces a gain/justification bug = many channels pinned near full-scale);
  - the frame-type histogram (the type[2] word: 0000 audio/filler, etc.).

  python3 -m reac.characterize CAPTURE.pcap [...]

Frame layout (reacdriver REACPacketHeader + obs-h8819, verified at 48k):
  payload = counter[2] + type[2] + data[32] + audio[1440] + ending[2]
  audio   = 12 time-samples x 40 channel-slots x 3 bytes, even/odd interleave.
"""
import sys
from collections import Counter
from dataclasses import dataclass, field

from .analyzer import analyze_stream
from .model import Frame
from .pcap import read_pcap_raw

_AUDIO_OFF = 36                       # counter(2) + type(2) + data(32)
_N_CH = 40
_N_SAMP = 12
_RES = 3
_STRIDE = _N_CH * _RES                # 120 B between successive time-samples
_AUDIO_LEN = _N_SAMP * _N_CH * _RES   # 1440
_FULLSCALE = 0x7FFFFF
_RATES = {44100: 3675.0, 48000: 4000.0, 96000: 8000.0}  # rate -> nominal pps (12 samp/pkt)


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
    rows = read_pcap_raw(path)
    r = Report(n_frames=len(rows))
    if not rows:
        r.summary = "no REAC (0x8819) frames in %s" % path
        return r

    r.payload_lens = [len(p) for (_t, _s, _v, _q, p) in rows]
    ts = [t for (t, *_rest) in rows]
    span = ts[-1] - ts[0]
    r.pps = (len(rows) - 1) / span if span > 0 else 0.0
    r.inferred_rate = min(_RATES, key=lambda rate: abs(r.pps - _RATES[rate])) if r.pps else 0

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

    rate_lbl = "%g kHz" % (r.inferred_rate / 1000.0) if r.inferred_rate else "?"
    r.summary = ("%s (%.0f pps); %d frames; %s B; loss %d / reord %d / dup %d; "
                 "%d slots, %d active, %d saturated; types %s") % (
        rate_lbl, r.pps, r.n_frames,
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
    print("--- interpret (rate is set BY pps; channels disambiguate the 96k model) ---")
    print("  pps ~4000 + ~40 active  -> 48 kHz, 40 ch")
    print("  pps ~8000 + ~40 active  -> 96 kHz double-pps   => REAC_MODE_96K = {96000,40,12}")
    print("  pps ~4000 + ~20 active  -> 96 kHz channel-halving => {96000,20,24}  (or 48k 20-ch)")
    print("  pps ~3675               -> 44.1 kHz             => add REAC_MODE_44K1 = {44100,40,12}")
    print("  many channels saturated (peak ~0x7FFFFF) -> gain/24-bit-justification bug, not transport")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
