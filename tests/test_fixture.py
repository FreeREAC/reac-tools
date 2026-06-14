# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Pau Aliagas <linuxnow@gmail.com>

"""The synthetic-from-real pcap fixture round-trips to known ground truth.

tests/fixtures/real_reac_stream.pcap is reconstructed from the real on-site
capture (payload-only tcpdump text, 2026-05-30): REAC-A console->broadcast,
src 00:40:ab:c9:91:9c, seqs 0xfd7e..0xfd81, ~242us spacing, no loss.

Reconstructed as full Ethernet frames (the wire was untagged, proven on-site).
Byte layout matches obs-h8819-source: eth14 + l2_counter(uint16 LE) at offset 14.
"""
import os
import unittest

from reac.pcap import read_pcap
from reac.analyzer import analyze_stream, jitter_stats

FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "real_reac_stream.pcap")


class TestRealFixture(unittest.TestCase):
    def test_fixture_exists(self):
        self.assertTrue(os.path.exists(FIXTURE), "fixture pcap missing; run tools/make_fixture.py")

    def test_parses_four_consecutive_frames(self):
        frames = read_pcap(FIXTURE)
        self.assertEqual(len(frames), 4)
        self.assertEqual([f.seq for f in frames], [0xfd7e, 0xfd7f, 0xfd80, 0xfd81])

    def test_source_mac_preserved(self):
        frames = read_pcap(FIXTURE)
        self.assertTrue(all(f.src == "00:40:ab:c9:91:9c" for f in frames))

    def test_analyzer_reports_clean(self):
        frames = read_pcap(FIXTURE)
        r = analyze_stream(frames)
        self.assertEqual((r.lost, r.reordered, r.duplicated), (0, 0, 0))

    def test_jitter_matches_real_spacing(self):
        # real spacing ~242-264us; at 3000fps nominal (333us) gap ratio < 1
        frames = read_pcap(FIXTURE)
        j = jitter_stats(frames, nominal_dt=1 / 3000)
        self.assertLess(j.max_gap_ratio, 1.5)


if __name__ == "__main__":
    unittest.main()
