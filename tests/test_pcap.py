# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Pau Aliagas <linuxnow@gmail.com>

"""Tests for reading/writing classic pcap files of REAC traffic."""
import os
import tempfile
import unittest

from reac.pcap import read_pcap, write_pcap
from reac.model import Frame


def _eth(dst, src, payload, ethertype=b"\x88\x19"):
    def mac(s):
        return bytes.fromhex(s.replace(":", ""))
    return mac(dst) + mac(src) + ethertype + payload


class TestPcapRoundTrip(unittest.TestCase):
    def test_write_then_read_preserves_frames(self):
        # one REAC frame: seq 0x1234 little-endian = bytes 34 12
        payload = b"\x34\x12" + b"\x00" * 100
        eth = _eth("ff:ff:ff:ff:ff:ff", "00:40:ab:c9:91:9c", payload)
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as fh:
            path = fh.name
        try:
            write_pcap(path, [(1.5, eth)])
            frames = read_pcap(path)
            self.assertEqual(len(frames), 1)
            self.assertEqual(frames[0].src, "00:40:ab:c9:91:9c")
            self.assertEqual(frames[0].seq, 0x1234)
            self.assertAlmostEqual(frames[0].ts, 1.5, places=6)
        finally:
            os.unlink(path)

    def test_read_skips_non_8819_frames(self):
        reac = _eth("ff:ff:ff:ff:ff:ff", "00:40:ab:c9:91:9c", b"\x01\x00" + b"\x00" * 60)
        ipv4 = _eth("aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66", b"\x00" * 60,
                    ethertype=b"\x08\x00")
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as fh:
            path = fh.name
        try:
            write_pcap(path, [(0.0, reac), (0.001, ipv4)])
            frames = read_pcap(path)
            self.assertEqual(len(frames), 1)  # only the 0x8819 one
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()
