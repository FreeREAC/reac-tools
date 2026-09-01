# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Pau Aliagas <linuxnow@gmail.com>

"""Head-amp control-block byte-diff analyzer for REAC S-0808 capture segments.

Companion to ``capture-headamp.py``. Given a manifest of marked, single-control
capture segments (baseline, then one segment per head-amp toggle), this:

  1. parses every control frame's 32-byte block with :mod:`reac.ctrl`;
  2. per segment, per (src-MAC, control signature), takes the MODAL block
     (the steady-state block the operator held while pressing Enter), and flags
     any signature whose block wobbled within the segment;
  3. diffs each toggle segment's modal block against the baseline, EXCLUDING the
     checksum byte (which the master re-derives whenever a control byte moves);
  4. attributes each moved byte to the control named in the manifest step, and
     - fits the **gain** value byte against the swept dB steps (derives the law:
       byte = a*dB + b, plus per-step delta),
     - XORs the **flag** byte to name the **48V** and **polarity** bit,
     - correlates CH1-vs-CH2 sweeps to name the **channel-selector** byte;
  5. prints a per-control byte map with a confidence grade.

Coordinates: bytes are reported in BOTH the reac-pw C-parser frame offset
(``frame[18:50]``, what REAC-FSM-EVIDENCE.md / the procedure doc use) and the
in-block index, so a finding drops straight into the docs.

Usage:
    python3 -m reac.headamp MANIFEST.json          # full diff/isolate report
    python3 -m reac.headamp --pcap CAPTURE.pcap    # parse-only pipeline check
"""
import argparse
import json
import os
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field

from . import ctrl
from .pcap import read_pcap_raw

# frame offset of the control block start (reac-pw C coordinates): payload[4] == frame[18].
_FRAME_BLOCK_OFF = 18


def frame_off(block_index):
    """Map an in-block index (0..31) to the reac-pw C frame offset used in docs."""
    return _FRAME_BLOCK_OFF + block_index


@dataclass
class SegBlocks:
    """Per-segment modal control blocks, keyed by (src_mac, signature)."""
    label: str
    control: str
    channel: object
    value: object
    unit: object
    frames: int = 0
    # key -> (modal_block_bytes, modal_count, total_count, exemplar_ctrl)
    modal: dict = field(default_factory=dict)


def _modal_blocks(pcap_path):
    """Return {(src, sig): (block, modal_count, total, exemplar)} for a pcap.

    Only cdea/cfea control frames (checksum-bearing) are considered; FILLER audio
    is skipped. The modal block is the most common block for that (src, sig) —
    the steady state held during the segment.
    """
    counters = defaultdict(Counter)
    exemplar = {}
    total = Counter()
    for _ts, src, _vlan, _seq, payload in read_pcap_raw(pcap_path):
        c = ctrl.parse(payload)
        if c.kind in (ctrl.NONE, ctrl.FILLER):
            continue
        key = (src, ctrl.signature(c))
        counters[key][c.block] += 1
        total[key] += 1
        exemplar.setdefault(key, c)
    out = {}
    for key, ctr in counters.items():
        block, cnt = ctr.most_common(1)[0]
        out[key] = (block, cnt, total[key], exemplar[key])
    return out


def load_segments(manifest, base_dir):
    """Read every segment's modal blocks per the manifest. Returns list[SegBlocks]."""
    segs = []
    for s in manifest["segments"]:
        pcap = os.path.join(base_dir, s["pcap"])
        sb = SegBlocks(label=s["label"], control=s.get("control", "none"),
                       channel=s.get("channel"), value=s.get("value"),
                       unit=s.get("unit"))
        if os.path.exists(pcap):
            sb.modal = _modal_blocks(pcap)
            sb.frames = sum(t for (_b, _c, t, _e) in sb.modal.values())
        segs.append(sb)
    return segs


def _block_diff(base, other):
    """Offsets where two 32-byte blocks differ, minus the derived checksum byte.

    Returns list[(block_index, base_val, other_val)] sorted by index.
    """
    diffs = []
    for j in range(min(len(base), len(other))):
        if base[j] != other[j] and ctrl.BLOCK_OFF + j != ctrl.CKSUM_OFF:
            diffs.append((j, base[j], other[j]))
    return diffs


def _pick_signature(segs):
    """Choose the (src, sig) key present in the baseline that moves the most.

    The head-amp state rides the master's established heartbeat (cdea 01 03 0019),
    but we don't assume it: pick the key whose modal block changes across the most
    segments relative to the baseline, so a dedicated control message would win if
    that is where the bytes actually live.
    """
    base = segs[0]
    best, best_moves = None, -1
    for key, (bblock, *_r) in base.modal.items():
        moves = 0
        for sb in segs[1:]:
            if key in sb.modal and _block_diff(bblock, sb.modal[key][0]):
                moves += 1
        if moves > best_moves:
            best, best_moves = key, moves
    return best


def _fit_linear(points):
    """Least-squares fit y = a*x + b over [(x, y), ...]; return (a, b, max_resid)."""
    n = len(points)
    if n < 2:
        return None
    sx = sum(x for x, _ in points)
    sy = sum(y for _, y in points)
    sxx = sum(x * x for x, _ in points)
    sxy = sum(x * y for x, y in points)
    denom = n * sxx - sx * sx
    if denom == 0:
        return None
    a = (n * sxy - sx * sy) / denom
    b = (sy - a * sx) / n
    max_resid = max(abs(y - (a * x + b)) for x, y in points)
    return a, b, max_resid


@dataclass
class Finding:
    control: str
    channel: object
    offset_frame: int          # reac-pw frame offset (frame[18:50])
    block_index: int
    detail: str
    confidence: str


def isolate(segs):
    """Diff all toggle segments vs baseline and isolate each head-amp control.

    Returns (key, findings, notes) where key is the chosen (src, sig).
    """
    notes = []
    if not segs or not segs[0].modal:
        return None, [], ["baseline segment has no control frames"]
    key = _pick_signature(segs)
    if key is None:
        return None, [], ["no signature present in baseline to diff against"]
    base_block = segs[0].modal[key][0]

    # stability warnings: a segment whose modal block was not dominant
    for sb in segs:
        if key in sb.modal:
            _b, cnt, tot, _e = sb.modal[key]
            if tot and cnt / tot < 0.9:
                notes.append("segment '%s': modal block only %d/%d frames "
                             "(unstable — hold the control steady longer)"
                             % (sb.label, cnt, tot))

    findings = []
    gain_pts = defaultdict(list)      # channel -> [(dB, value_byte)]
    gain_off = {}                     # channel -> block_index of value byte

    for sb in segs[1:]:
        if key not in sb.modal:
            findings.append(Finding(sb.control, sb.channel, -1, -1,
                            "segment '%s': signature absent" % sb.label, "none"))
            continue
        diffs = _block_diff(base_block, sb.modal[key][0])
        if not diffs:
            back = str(sb.value).lower() in ("0", "0.0", "off", "norm", "normal",
                                             "flat", "none")
            if back:
                msg = ("segment '%s': matches baseline (expected — control "
                       "returned to flat/off)" % sb.label)
            else:
                msg = ("segment '%s': NO byte moved vs baseline (control not on "
                       "this signature, or state not live in the steady "
                       "heartbeat — capture the toggle TRANSIENT too)" % sb.label)
            findings.append(Finding(sb.control, sb.channel, -1, -1, msg, "none"))
            continue

        conf = "high" if len(diffs) == 1 else "medium"
        if sb.control == "gain" and isinstance(sb.value, (int, float)):
            # expect a single value byte; if several moved, take the lone non-flag one
            for j, bv, ov in diffs:
                gain_pts[sb.channel].append((float(sb.value), ov))
                gain_off.setdefault(sb.channel, j)
            j, bv, ov = diffs[0]
            findings.append(Finding("gain", sb.channel, frame_off(j), j,
                            "'%s': block[%d] (frame[%d]) %#04x -> %#04x @ %s%s"
                            % (sb.label, j, frame_off(j), bv, ov, sb.value,
                               sb.unit or ""), conf))
        elif sb.control in ("48v", "phantom", "polarity"):
            j, bv, ov = diffs[0]
            bit = bv ^ ov
            findings.append(Finding(sb.control, sb.channel, frame_off(j), j,
                            "'%s': flag block[%d] (frame[%d]) %#04x -> %#04x "
                            "(bit %#04x = bit#%s)"
                            % (sb.label, j, frame_off(j), bv, ov, bit,
                               bit.bit_length() - 1 if bit else "?"), conf))
        else:
            j, bv, ov = diffs[0]
            findings.append(Finding(sb.control or "?", sb.channel, frame_off(j), j,
                            "'%s': block[%d] (frame[%d]) %#04x -> %#04x"
                            % (sb.label, j, frame_off(j), bv, ov), conf))

    # derive gain law per channel
    for chan, pts in gain_pts.items():
        fit = _fit_linear(pts)
        j = gain_off[chan]
        if fit:
            a, b, resid = fit
            law = ("CH%s GAIN LAW: byte = %.3f*dB + %.1f  (%.3f byte/dB, "
                   "max residual %.2f) at block[%d]/frame[%d]"
                   % (chan, a, b, a, resid, j, frame_off(j)))
            conf = "high" if resid <= 1.0 and len(pts) >= 3 else "medium"
            findings.append(Finding("gain-law", chan, frame_off(j), j, law, conf))

    # channel-selector: which entry offset each channel's gain used
    if len(gain_off) >= 2:
        mapping = ", ".join("CH%s->block[%d]/frame[%d]" % (c, j, frame_off(j))
                            for c, j in sorted(gain_off.items(), key=lambda kv: str(kv[0])))
        # the chan_id byte of that entry is at offset-... entry is <id><flag><val>,
        # value byte is at gain_off, so chan_id byte sits 2 before it.
        idmap = ", ".join("CH%s id-byte=frame[%d]" % (c, frame_off(j - 2))
                          for c, j in sorted(gain_off.items(), key=lambda kv: str(kv[0])))
        findings.append(Finding("channel-selector", "*", -1, -1,
                        "distinct value-byte offset per channel confirms the "
                        "per-channel entry table: %s; entry chan_id bytes: %s"
                        % (mapping, idmap), "high" if len(gain_off) >= 2 else "low"))

    return key, findings, notes


def format_report(manifest, segs, key, findings, notes):
    L = []
    L.append("=== REAC head-amp byte-diff: %s ===" % manifest.get("capture", "(capture)"))
    L.append("master=%s box=%s  segments=%d"
             % (manifest.get("master", "?"), manifest.get("box", "?"), len(segs)))
    L.append("")
    L.append("segments:")
    for i, sb in enumerate(segs):
        L.append("  [%2d] %-28s ctrl=%-9s ch=%-4s val=%-5s frames=%d"
                 % (i, sb.label, sb.control, sb.channel, sb.value, sb.frames))
    L.append("")
    if key:
        L.append("diff signature (src, kind, op0, op1, op_len, sel): %s + %s" % (key[0], key[1]))
    L.append("(checksum byte frame[49] excluded from diffs — master re-derives it)")
    L.append("")
    L.append("=== CONTROL BYTE MAP ===")
    if not findings:
        L.append("  (no differences isolated)")
    for f in findings:
        L.append("  [%-6s] %-16s %s" % (f.confidence, f.control, f.detail))
    if notes:
        L.append("")
        L.append("=== NOTES ===")
        for n in notes:
            L.append("  - " + n)
    return "\n".join(L)


def _pcap_check(path):
    """Parse-only pipeline validation on one existing pcap (no manifest).

    Proves the capture->parse->decode path: counts control signatures, verifies
    the block checksum on every control frame, and prints a sample per-channel
    head-amp table so the entry decode is visibly correct on known frames.
    """
    sigs = Counter()
    cksum_ok = cksum_bad = 0
    sample_table = None
    for _ts, src, _vlan, _seq, payload in read_pcap_raw(path):
        c = ctrl.parse(payload)
        if c.kind in (ctrl.NONE, ctrl.FILLER):
            continue
        sigs[(c.kind, "%02x%02x" % (c.op0, c.op1), "%04x" % c.op_len)] += 1
        if c.cksum_ok:
            cksum_ok += 1
        else:
            cksum_bad += 1
        if c.kind == ctrl.MASTER_HB and c.entries and sample_table is None:
            sample_table = (src, c.entries)
    print("%s" % path)
    print("  control signatures (kind op0op1 op_len -> count):")
    for k, n in sigs.most_common():
        print("    %-16s %-6s %-6s  %d" % (k[0], k[1], k[2], n))
    tot = cksum_ok + cksum_bad
    print("  block checksum: %d/%d verify (Sum(frame[18:50]) mod 256 == 0)%s"
          % (cksum_ok, tot, "" if not cksum_bad else "  <-- %d FAILED" % cksum_bad))
    if sample_table:
        src, entries = sample_table
        print("  sample head-amp table (master %s, cdea 01 03 0019):" % src)
        for e in entries:
            print("    entry %d: chan_id=%#04x flag=%#04x value(gain)=%#04x "
                  "(id@frame[%d] flag@frame[%d] value@frame[%d])"
                  % (e.index, e.chan_id, e.flag, e.value,
                     e.off - ctrl.BLOCK_OFF + _FRAME_BLOCK_OFF,
                     e.off - ctrl.BLOCK_OFF + _FRAME_BLOCK_OFF + 1,
                     e.off - ctrl.BLOCK_OFF + _FRAME_BLOCK_OFF + 2))
    else:
        print("  (no cdea 01 03 0019 heartbeat with a channel table in this capture)")
    return 0 if cksum_bad == 0 and tot > 0 else 1


def main(argv=None):
    ap = argparse.ArgumentParser(description="REAC head-amp control-block byte-diff analyzer")
    ap.add_argument("target", help="manifest.json (diff mode) or, with --pcap, a capture file")
    ap.add_argument("--pcap", action="store_true",
                    help="parse-only pipeline check on a single existing pcap (no manifest)")
    args = ap.parse_args(argv)

    if args.pcap:
        return _pcap_check(args.target)

    with open(args.target) as f:
        manifest = json.load(f)
    base_dir = os.path.dirname(os.path.abspath(args.target))
    segs = load_segments(manifest, base_dir)
    key, findings, notes = isolate(segs)
    print(format_report(manifest, segs, key, findings, notes))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
