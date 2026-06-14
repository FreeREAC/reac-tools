# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Pau Aliagas <linuxnow@gmail.com>

"""Round-trip tests: simulator injects a known fault, analyzer must detect it.

This is the core confidence check for the whole toolkit. If the simulator
produces a stream with N lost frames and the analyzer reports N, we trust the
analyzer on real on-site captures.
"""
import unittest

from reac.analyzer import analyze_stream, detect_crossmix, jitter_stats
from reac.simulator import simulate_stream

A_SRC = "00:40:ab:c9:91:9c"
B_SRC = "00:40:ab:c9:91:9d"


class TestSimulatorRoundTrip(unittest.TestCase):
    def test_clean_stream_is_clean(self):
        frames = simulate_stream(n=1000, src=A_SRC, vlan=11)
        r = analyze_stream(frames)
        self.assertEqual((r.lost, r.reordered, r.duplicated), (0, 0, 0))

    def test_injected_loss_is_detected(self):
        # drop 5 specific frames
        frames = simulate_stream(n=1000, src=A_SRC, vlan=11, drop_indices=[100, 200, 201, 500, 900])
        r = analyze_stream(frames)
        self.assertEqual(r.lost, 5)

    def test_injected_duplicate_is_detected(self):
        frames = simulate_stream(n=500, src=A_SRC, vlan=11, dup_indices=[50, 60])
        r = analyze_stream(frames)
        self.assertEqual(r.duplicated, 2)
        self.assertEqual(r.lost, 0)

    def test_injected_reorder_is_detected(self):
        frames = simulate_stream(n=500, src=A_SRC, vlan=11, swap_indices=[100])
        r = analyze_stream(frames)
        self.assertEqual(r.reordered, 1)
        self.assertEqual(r.lost, 0)

    def test_injected_crossmix_is_detected(self):
        # 3 frames of stream B leak into stream A's capture
        frames = simulate_stream(n=500, src=A_SRC, vlan=11,
                                 crossmix_indices=[10, 20, 30],
                                 crossmix_src=B_SRC, crossmix_vlan=12)
        foreign = detect_crossmix(frames, expect_vlan=11, expect_src=A_SRC)
        self.assertEqual(len(foreign), 3)

    def test_injected_jitter_burst_is_detected(self):
        # a 10x burst at index 250
        frames = simulate_stream(n=500, src=A_SRC, vlan=11,
                                 nominal_dt=0.000333, burst_at=250, burst_mult=10.0)
        s = jitter_stats(frames, nominal_dt=0.000333)
        self.assertGreaterEqual(s.max_gap_ratio, 9.9)


if __name__ == "__main__":
    unittest.main()
