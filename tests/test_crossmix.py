# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Pau Aliagas <linuxnow@gmail.com>

"""Tests for A/B cross-mix detection.

On the rig, REAC-A (VLAN 11, console src MAC X) and REAC-B (VLAN 12, src Y)
share dst=broadcast + ethertype 0x8819. The ONLY discriminator is the VLAN
tag. If isolation leaks, a port that should carry one stream sees frames from
the other -> the stagebox decodes foreign frames -> clicking.

detect_crossmix(frames, expect_vlan=, expect_src=) returns the list of frames
that DON'T belong (foreign vlan or foreign src).
"""
import unittest

from reac.analyzer import detect_crossmix
from reac.model import Frame


def F(seq, vlan, src):
    return Frame(ts=seq * 0.000333, src=src, vlan=vlan, seq=seq, payload_len=1478)


A_SRC = "00:40:ab:c9:91:9c"
B_SRC = "00:40:ab:c9:91:9d"


class TestCrossMix(unittest.TestCase):
    def test_pure_stream_has_no_foreign_frames(self):
        frames = [F(i, vlan=11, src=A_SRC) for i in range(5)]
        foreign = detect_crossmix(frames, expect_vlan=11, expect_src=A_SRC)
        self.assertEqual(foreign, [])

    def test_frame_from_other_vlan_is_foreign(self):
        frames = [F(0, 11, A_SRC), F(1, 12, B_SRC), F(2, 11, A_SRC)]
        foreign = detect_crossmix(frames, expect_vlan=11, expect_src=A_SRC)
        self.assertEqual(len(foreign), 1)
        self.assertEqual(foreign[0].vlan, 12)

    def test_frame_from_other_src_same_vlan_is_foreign(self):
        # tag stripped/leaked: right vlan but wrong console source
        frames = [F(0, 11, A_SRC), F(1, 11, B_SRC)]
        foreign = detect_crossmix(frames, expect_vlan=11, expect_src=A_SRC)
        self.assertEqual(len(foreign), 1)
        self.assertEqual(foreign[0].src, B_SRC)


if __name__ == "__main__":
    unittest.main()
