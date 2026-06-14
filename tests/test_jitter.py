# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Pau Aliagas <linuxnow@gmail.com>

"""Tests for inter-arrival jitter analysis.

REAC needs tightly, regularly spaced frames. A burst (one large inter-arrival
gap) breaks the stagebox's sample-clock lock -> LED flashes -> clicking.
jitter_stats(frames, nominal_dt=) returns timing stats and a worst-case gap
expressed as a multiple of the nominal frame interval.
"""
import unittest

from reac.analyzer import jitter_stats
from reac.model import Frame


def at(times):
    return [Frame(ts=t, src="x", vlan=11, seq=i, payload_len=1478)
            for i, t in enumerate(times)]


class TestJitter(unittest.TestCase):
    def test_evenly_spaced_has_max_gap_ratio_one(self):
        times = [0.0, 0.001, 0.002, 0.003]
        s = jitter_stats(at(times), nominal_dt=0.001)
        self.assertAlmostEqual(s.max_gap_ratio, 1.0, places=6)

    def test_burst_gap_reported_as_ratio(self):
        # one 5ms gap among 1ms spacing -> worst gap is 5x nominal
        times = [0.0, 0.001, 0.006, 0.007]
        s = jitter_stats(at(times), nominal_dt=0.001)
        self.assertAlmostEqual(s.max_gap_ratio, 5.0, places=6)

    def test_mean_dt_computed(self):
        times = [0.0, 0.002, 0.004]
        s = jitter_stats(at(times), nominal_dt=0.002)
        self.assertAlmostEqual(s.mean_dt, 0.002, places=6)


if __name__ == "__main__":
    unittest.main()
