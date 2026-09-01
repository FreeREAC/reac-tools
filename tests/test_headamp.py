# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Pau Aliagas <linuxnow@gmail.com>

"""Round-trip test for the head-amp byte-diff analyzer.

Synthesizes a full capture campaign with a KNOWN head-amp encoding (gain law
byte=2*dB on slot 0, a 48V bit, a polarity bit, and a CH2 gain on slot 1), writes
per-segment pcaps + a manifest exactly as capture-headamp.py would, then asserts
reac.headamp.isolate recovers each control — so the analyzer is trustworthy
before it meets tomorrow's real S-0808 grab.
"""
import os
import tempfile
import unittest

from reac import headamp
from reac.pcap import write_pcap
from test_ctrl import build_heartbeat

# Known synthetic head-amp encoding:
#   CH1 -> slot 0 (chan_id 0x11): value byte = 2*dB ; flag base 0x28
#   CH2 -> slot 1 (chan_id 0x12): value byte = 2*dB
#   48V  bit = 0x40 in the channel's flag
#   POL  bit = 0x80 in the channel's flag
GAIN_A = 2.0
V48 = 0x40
VPOL = 0x80


def _entries(ch1_gain=0, ch1_flag=0x28, ch2_gain=0, ch2_flag=0x28):
    base = [(0x11, ch1_flag, ch1_gain & 0xFF), (0x12, ch2_flag, ch2_gain & 0xFF)]
    base += [(0x13 + i, 0x28, 0x00) for i in range(6)]     # slots 2..7 static
    return base


def _write_seg(path, entries, n=20):
    frames = [((i * 0.00025), build_heartbeat(entries, counter=i)) for i in range(n)]
    write_pcap(path, frames)


class TestHeadampIsolate(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        # (label, control, channel, value, entries)
        plan = [
            ("baseline", "none", None, None, _entries()),
            ("CH1 +10", "gain", 1, 10, _entries(ch1_gain=int(GAIN_A * 10))),
            ("CH1 +20", "gain", 1, 20, _entries(ch1_gain=int(GAIN_A * 20))),
            ("CH1 +30", "gain", 1, 30, _entries(ch1_gain=int(GAIN_A * 30))),
            ("CH1 +40", "gain", 1, 40, _entries(ch1_gain=int(GAIN_A * 40))),
            ("CH1 flat", "gain", 1, 0, _entries(ch1_gain=0)),
            ("CH1 48V on", "48v", 1, "on", _entries(ch1_flag=0x28 | V48)),
            ("CH1 48V off", "48v", 1, "off", _entries(ch1_flag=0x28)),
            ("CH1 pol inv", "polarity", 1, "on", _entries(ch1_flag=0x28 | VPOL)),
            ("CH1 pol norm", "polarity", 1, "off", _entries(ch1_flag=0x28)),
            ("CH2 +20", "gain", 2, 20, _entries(ch2_gain=int(GAIN_A * 20))),
            ("CH2 flat", "gain", 2, 0, _entries(ch2_gain=0)),
        ]
        segs = []
        for i, (label, control, ch, val, entries) in enumerate(plan):
            name = "seg%02d.pcap" % i
            _write_seg(os.path.join(self.d, name), entries)
            segs.append(dict(index=i, label=label, control=control, channel=ch,
                             value=val, unit="dB" if control == "gain" else None,
                             pcap=name))
        self.manifest = dict(capture="synthetic", master="TEST", box="S-0808",
                             segments=segs)

    def _findings(self):
        segs = headamp.load_segments(self.manifest, self.d)
        return headamp.isolate(segs)

    def test_gain_law_recovered(self):
        _key, findings, _notes = self._findings()
        laws = [f for f in findings if f.control == "gain-law" and f.channel == 1]
        self.assertTrue(laws, "no CH1 gain law derived")
        self.assertEqual(laws[0].confidence, "high")
        self.assertIn("%.3f*dB" % GAIN_A, laws[0].detail)   # a == 2.000

    def test_gain_byte_offset_is_slot0_value(self):
        _key, findings, _notes = self._findings()
        # CH1 gain byte sits at frame[25] (slot 0 value); CH2 at frame[28] (slot 1).
        # CH1 is fully swept -> a law; CH2 is only nudged +20 (procedure confirms
        # the selector, not a full CH2 law) -> checked via its per-segment finding.
        ch1law = [f for f in findings if f.control == "gain-law" and f.channel == 1]
        self.assertEqual(ch1law[0].offset_frame, 25)
        ch2 = [f for f in findings if f.control == "gain" and f.channel == 2
               and f.offset_frame > 0]
        self.assertTrue(ch2)
        self.assertEqual(ch2[0].offset_frame, 28)

    def test_48v_bit_isolated(self):
        _key, findings, _notes = self._findings()
        v = [f for f in findings if f.control == "48v" and "-> " in f.detail]
        self.assertTrue(v)
        self.assertTrue(any(("%#04x" % V48) in f.detail for f in v),
                        "48V bit 0x40 not named: %s" % [f.detail for f in v])

    def test_polarity_bit_isolated(self):
        _key, findings, _notes = self._findings()
        p = [f for f in findings if f.control == "polarity"]
        self.assertTrue(any(("%#04x" % VPOL) in f.detail for f in p),
                        "polarity bit 0x80 not named: %s" % [f.detail for f in p])

    def test_channel_selector_distinguishes_ch1_ch2(self):
        _key, findings, _notes = self._findings()
        sel = [f for f in findings if f.control == "channel-selector"]
        self.assertTrue(sel)
        self.assertIn("frame[25]", sel[0].detail)          # CH1 slot-0 value byte
        self.assertIn("frame[28]", sel[0].detail)          # CH2 slot-1 value byte

    def test_baseline_has_no_spurious_change(self):
        # a toggle that returns to flat must diff clean vs baseline (no phantom byte)
        _key, findings, _notes = self._findings()
        flat = [f for f in findings if "'CH1 flat'" in f.detail]
        self.assertTrue(flat)
        # return-to-flat matches baseline; reported as expected, not a spurious byte
        self.assertTrue(all("matches baseline" in f.detail for f in flat))


if __name__ == "__main__":
    unittest.main()
