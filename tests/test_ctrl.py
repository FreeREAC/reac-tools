# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Pau Aliagas <linuxnow@gmail.com>

"""Tests for reac.ctrl — the control-block parser + checksum + entry decode."""
import os
import unittest

from reac import ctrl
from reac.pcap import read_pcap_raw

_CORPUS = os.path.join(os.path.dirname(__file__), "..", "..",
                       "reac-captures", "captures")


def build_heartbeat(entries, sel=0x01, counter=0, src=b"\x00\x40\xab\xc9\xcc\x03",
                    dst=b"\xff\xff\xff\xff\xff\xff", pad_to=60):
    """Build a full ethernet cdea 01 03 0019 heartbeat carrying up to 8 triplets.

    entries: list of (chan_id, flag, value) placed into fixed slots 0.. ; missing
    slots are zero-filled. Applies the block checksum at frame[49] so the block
    sums to 0 mod 256 (exactly as the master does on the wire).
    """
    f = bytearray(max(pad_to, 50))
    f[0:6] = dst
    f[6:12] = src
    f[12:14] = b"\x88\x19"
    f[14:16] = counter.to_bytes(2, "little")
    f[16:18] = b"\xcd\xea"                 # cdea control
    f[18] = 0x01
    f[19] = 0x03
    f[20:22] = (0x0019).to_bytes(2, "big")
    f[22] = sel
    for slot, (cid, flag, val) in enumerate(entries[:8]):
        o = 23 + slot * 3                  # frame[23] = block offset 5
        f[o] = cid
        f[o + 1] = flag
        f[o + 2] = val
    # checksum: frame[49] so Sum(frame[18:50]) % 256 == 0
    s = sum(f[18:49]) & 0xFF
    f[49] = (256 - s) & 0xFF
    return bytes(f)


class TestChecksum(unittest.TestCase):
    def test_apply_and_verify(self):
        f = build_heartbeat([(0x11, 0x28, 0x00)])
        payload = f[14:]                   # what read_pcap_raw yields
        self.assertTrue(ctrl.checksum_ok(payload))
        self.assertEqual(sum(payload[ctrl.BLOCK_OFF:ctrl.BLOCK_END]) & 0xFF, 0)

    def test_mutation_breaks_checksum(self):
        f = bytearray(build_heartbeat([(0x11, 0x28, 0x00)]))
        f[25] = 0x2A                       # move a gain byte, don't re-derive cksum
        self.assertFalse(ctrl.checksum_ok(f[14:]))


class TestParse(unittest.TestCase):
    def test_classify_heartbeat(self):
        c = ctrl.parse(build_heartbeat([(0x11, 0x28, 0x00)])[14:])
        self.assertEqual(c.kind, ctrl.MASTER_HB)
        self.assertEqual((c.op0, c.op1, c.op_len, c.sel), (0x01, 0x03, 0x0019, 0x01))
        self.assertTrue(c.cksum_ok)

    def test_entry_decode_skips_separators(self):
        # slot 2 is a 'fe 00 00' separator (flag 0) -> not a channel
        c = ctrl.parse(build_heartbeat(
            [(0x11, 0x28, 0x05), (0x12, 0x28, 0x06), (0xfe, 0x00, 0x00),
             (0x00, 0x28, 0x07)])[14:])
        chans = [(e.chan_id, e.value) for e in c.entries]
        self.assertIn((0x11, 0x05), chans)
        self.assertIn((0x00, 0x07), chans)          # channel id 0 kept (flag!=0)
        self.assertNotIn(0xfe, [e.chan_id for e in c.entries])   # separator dropped

    def test_entry_offsets(self):
        c = ctrl.parse(build_heartbeat([(0x11, 0x28, 0x00)])[14:])
        e0 = c.entries[0]
        # first slot's chan_id is payload[9] == frame[23]; value two bytes later
        self.assertEqual(e0.off, 9)                 # payload offset of chan_id
        self.assertEqual(e0.off + 2, 11)            # payload offset of value == frame[25]


class TestRealCorpus(unittest.TestCase):
    @unittest.skipUnless(
        os.path.exists(os.path.join(_CORPUS, "matrix-m200-s0808-2026-07-11.pcap")),
        "corpus capture not present")
    def test_all_control_frames_checksum_verify(self):
        path = os.path.join(_CORPUS, "matrix-m200-s0808-2026-07-11.pcap")
        seen = ok = 0
        for _t, _s, _v, _q, payload in read_pcap_raw(path):
            c = ctrl.parse(payload)
            if c.kind in (ctrl.NONE, ctrl.FILLER):
                continue
            seen += 1
            ok += 1 if c.cksum_ok else 0
        self.assertGreater(seen, 0)
        self.assertEqual(ok, seen)                  # every cdea/cfea block checksums

    @unittest.skipUnless(
        os.path.exists(os.path.join(_CORPUS, "matrix-m200-s0808-2026-07-11.pcap")),
        "corpus capture not present")
    def test_corpus_gain_byte_is_zero(self):
        """The FSM-evidence claim (task #155): gain byte 0x00 across the corpus."""
        path = os.path.join(_CORPUS, "matrix-m200-s0808-2026-07-11.pcap")
        for _t, _s, _v, _q, payload in read_pcap_raw(path):
            c = ctrl.parse(payload)
            if c.kind == ctrl.MASTER_HB:
                for e in c.entries:
                    self.assertEqual(e.value, 0x00)


if __name__ == "__main__":
    unittest.main()
