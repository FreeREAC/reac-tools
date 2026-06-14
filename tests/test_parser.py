# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Pau Aliagas <linuxnow@gmail.com>

"""Tests for parsing real tcpdump text captures into Frame objects.

Two real formats from the rig (GL-MT6000, OpenWrt 25.12, busybox tcpdump):

A) `tcpdump -e -xx` full ethernet frame, bridge egress shows a reconstructed
   802.1Q tag (the known artifact):
     HH:MM:SS.uuuuuu SRC > DST, ethertype 802.1Q (0x8100), length 632: vlan 11, ...
        0x0000:  0040 abc9 919c 0040 abc4 803b 8100 000b
        0x0010:  8819 603d 0000 ...

B) `tcpdump -xx` (no -e) payload-only after link header strip:
     HH:MM:SS.uuuuuu SRC > DST, ethertype Unknown (0x8819), length 1496: ...
        0x0000:  7efd 0000 000e ...   <- REAC payload starts here, seq = 0xfd7e LE
"""
import unittest

from reac.parser import parse_tcpdump_text

CAP_A = """\
10:54:34.777965 00:40:ab:c4:80:3b > 00:40:ab:c9:91:9c, ethertype 802.1Q (0x8100), length 632: vlan 11, p 0, ethertype Unknown (0x8819),
\t0x0000:  0040 abc9 919c 0040 abc4 803b 8100 000b  .@.....@...;....
\t0x0010:  8819 603d 0000 0000 0000 0000 0000 0000  ..`=............
10:54:34.778364 00:40:ab:c4:80:3b > 00:40:ab:c9:91:9c, ethertype 802.1Q (0x8100), length 632: vlan 11, p 0, ethertype Unknown (0x8819),
\t0x0000:  0040 abc9 919c 0040 abc4 803b 8100 000b  .@.....@...;....
\t0x0010:  8819 613d 0000 0000 0000 0000 0000 0000  ..a=............
"""

CAP_B = """\
09:03:13.527981 00:40:ab:c9:91:9c > ff:ff:ff:ff:ff:ff, ethertype Unknown (0x8819), length 1496:
\t0x0000:  7efd 0000 000e 000e 000e 000e 000e 000e  ~...............
\t0x0010:  000e 000e 000e 000e 000e 000e 000e 000e  ................
09:03:13.528223 00:40:ab:c9:91:9c > ff:ff:ff:ff:ff:ff, ethertype Unknown (0x8819), length 1496:
\t0x0000:  7ffd 0000 000e 000e 000e 000e 000e 000e  ................
\t0x0010:  000e 000e 000e 000e 000e 000e 000e 000e  ................
"""


class TestParser(unittest.TestCase):
    def test_parses_frame_count(self):
        frames = parse_tcpdump_text(CAP_A)
        self.assertEqual(len(frames), 2)

    def test_extracts_src_dst_vlan(self):
        f = parse_tcpdump_text(CAP_A)[0]
        self.assertEqual(f.src, "00:40:ab:c4:80:3b")
        self.assertEqual(f.vlan, 11)

    def test_full_frame_seq_is_after_8819_little_endian(self):
        # payload starts 60 3d -> LE 0x3d60
        frames = parse_tcpdump_text(CAP_A)
        self.assertEqual(frames[0].seq, 0x3d60)
        self.assertEqual(frames[1].seq, 0x3d61)  # 61 3d LE

    def test_payload_only_seq_from_offset_zero(self):
        # 7e fd -> LE 0xfd7e
        frames = parse_tcpdump_text(CAP_B)
        self.assertEqual(frames[0].seq, 0xfd7e)
        self.assertEqual(frames[1].seq, 0xfd7f)

    def test_payload_only_has_no_vlan(self):
        f = parse_tcpdump_text(CAP_B)[0]
        self.assertIsNone(f.vlan)


if __name__ == "__main__":
    unittest.main()
