# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Pau Aliagas <linuxnow@gmail.com>

"""Tests for the capture-characterize analysis (the on-rig decision-tree tool).

Given a REAC pcap, `characterize` reports the rate fingerprint (pps -> 44.1/48/96
kHz), frame size, sequence health, per-channel levels (active-channel count +
saturation), and the frame-type histogram. Asserted against the real 4-frame
48 kHz fixture.
"""
import os
import unittest

from reac.characterize import characterize

FIX = os.path.join(os.path.dirname(__file__), "fixtures", "real_reac_stream.pcap")


class TestCharacterize(unittest.TestCase):
    def setUp(self):
        self.r = characterize(FIX)

    def test_frame_count_and_size(self):
        self.assertEqual(self.r.n_frames, 4)
        # REAC 48k L2 payload (after ethertype) = 1478 B (1492 B frame)
        self.assertEqual(set(self.r.payload_lens), {1478})

    def test_rate_fingerprint(self):
        # 4 frames over ~739 us -> ~4060 pps -> nearest REAC rate = 48 kHz
        self.assertEqual(self.r.inferred_rate, 48000)
        self.assertAlmostEqual(self.r.pps, 4060, delta=200)

    def test_sequence_clean(self):
        self.assertEqual(self.r.loss, 0)
        self.assertEqual(self.r.reordered, 0)
        self.assertEqual(self.r.duplicated, 0)

    def test_channels_analyzed(self):
        # canonical REAC frame de-interleaves to 40 channel slots
        self.assertEqual(self.r.n_channels, 40)
        self.assertEqual(len(self.r.channel_peak), 40)

    def test_model_hint(self):
        # 48k baseline: ~4000 pps -> the 48k/double-pps frame shape, not 96k
        self.assertIn("48", self.r.summary)


if __name__ == "__main__":
    unittest.main()
