# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Pau Aliagas <linuxnow@gmail.com>

"""Tests for dual-point loss diff.

Capture the SAME REAC stream at the console side (sender) and the box side
(receiver). Frames present at the sender but missing at the receiver were
lost crossing the link. This is the decisive on-site measurement.
"""
import unittest

from reac.diff import diff_streams
from reac.model import Frame


def F(seq):
    return Frame(ts=seq * 0.000333, src="x", vlan=11, seq=seq, payload_len=1478)


class TestDiff(unittest.TestCase):
    def test_identical_streams_no_loss(self):
        sender = [F(i) for i in range(10)]
        receiver = [F(i) for i in range(10)]
        r = diff_streams(sender, receiver)
        self.assertEqual(r.lost_in_transit, [])
        self.assertEqual(r.loss_count, 0)

    def test_missing_at_receiver_is_loss_in_transit(self):
        sender = [F(i) for i in range(10)]
        receiver = [F(i) for i in range(10) if i not in (3, 7)]
        r = diff_streams(sender, receiver)
        self.assertEqual(sorted(r.lost_in_transit), [3, 7])
        self.assertEqual(r.loss_count, 2)

    def test_extra_at_receiver_is_flagged(self):
        # a frame at the receiver not sent by this sender = cross-mix/foreign
        sender = [F(i) for i in range(5)]
        receiver = [F(i) for i in range(5)] + [F(999)]
        r = diff_streams(sender, receiver)
        self.assertEqual(r.unexpected_at_receiver, [999])

    def test_loss_rate(self):
        sender = [F(i) for i in range(100)]
        receiver = [F(i) for i in range(100) if i % 10 != 0]  # drop 10
        r = diff_streams(sender, receiver)
        self.assertEqual(r.loss_count, 10)
        self.assertAlmostEqual(r.loss_rate, 0.10, places=6)


if __name__ == "__main__":
    unittest.main()
