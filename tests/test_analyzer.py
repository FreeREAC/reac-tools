# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Pau Aliagas <linuxnow@gmail.com>

"""Tests for the REAC stream analyzer's loss detection."""
import unittest

from reac.analyzer import analyze_stream
from reac.model import Frame


def _seq_frames(seqs, src="aa:bb:cc:00:00:01", vlan=11, t0=0.0, dt=0.000333):
    """Build a list of Frames with the given sequence numbers, evenly spaced."""
    return [
        Frame(ts=t0 + i * dt, src=src, vlan=vlan, seq=s, payload_len=1478)
        for i, s in enumerate(seqs)
    ]


class TestLossDetection(unittest.TestCase):
    def test_clean_consecutive_sequence_reports_no_loss(self):
        frames = _seq_frames([10, 11, 12, 13, 14])
        report = analyze_stream(frames)
        self.assertEqual(report.lost, 0)

    def test_single_gap_reports_one_lost_frame(self):
        # 12 is missing between 11 and 13
        frames = _seq_frames([10, 11, 13, 14])
        report = analyze_stream(frames)
        self.assertEqual(report.lost, 1)

    def test_wrap_around_is_not_counted_as_loss(self):
        # 16-bit counter wraps 65535 -> 0
        frames = _seq_frames([65534, 65535, 0, 1])
        report = analyze_stream(frames)
        self.assertEqual(report.lost, 0)


class TestReorderDetection(unittest.TestCase):
    def test_in_order_reports_no_reorder(self):
        frames = _seq_frames([10, 11, 12, 13])
        report = analyze_stream(frames)
        self.assertEqual(report.reordered, 0)

    def test_swapped_pair_reports_one_reorder(self):
        # 11 arrives after 12
        frames = _seq_frames([10, 12, 11, 13])
        report = analyze_stream(frames)
        self.assertEqual(report.reordered, 1)
        # a reorder is not a real loss
        self.assertEqual(report.lost, 0)


class TestDuplicateDetection(unittest.TestCase):
    def test_no_duplicates(self):
        frames = _seq_frames([10, 11, 12])
        report = analyze_stream(frames)
        self.assertEqual(report.duplicated, 0)

    def test_repeated_sequence_reports_one_duplicate(self):
        frames = _seq_frames([10, 11, 11, 12])
        report = analyze_stream(frames)
        self.assertEqual(report.duplicated, 1)
        self.assertEqual(report.lost, 0)


if __name__ == "__main__":
    unittest.main()
