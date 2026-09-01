# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Pau Aliagas <linuxnow@gmail.com>

"""Tests for reac.observe — frame sighting, width formula, role aggregation.

Socket-free: everything below feeds synthetic ethernet frames to the pure
layers (sight / Segments), which is the whole aggregation path minus recvmsg.
"""
import unittest

from reac import observe

MASTER = bytes.fromhex("0040abc9cc03")
BOX = bytes.fromhex("0040abc9cc10")
BCAST = b"\xff" * 6


def eth(dst, src, payload, vlan=None):
    """A raw ethernet frame, optionally with an inline 802.1Q tag."""
    if vlan is None:
        return dst + src + b"\x88\x19" + payload
    return dst + src + b"\x81\x00" + vlan.to_bytes(2, "big") + b"\x88\x19" + payload


def filler_payload(eth_len, type_word=b"\x00\x00"):
    """A FILLER-classified payload sized so the FRAME is eth_len bytes."""
    body = b"\x00\x00" + type_word
    return body + b"\x00" * (eth_len - 14 - len(body))


class TestAudioWidth(unittest.TestCase):
    def test_family_solutions(self):
        self.assertEqual(observe.audio_width(1492), 40)   # downstream program
        self.assertEqual(observe.audio_width(1204), 32)   # S-4000 return
        self.assertEqual(observe.audio_width(628), 16)    # S-1608 return
        self.assertEqual(observe.audio_width(630), 16)    # + OHRCA FCS residue

    def test_non_solutions_refused(self):
        self.assertIsNone(observe.audio_width(53))        # not on the lattice
        self.assertIsNone(observe.audio_width(160))       # nch 3: odd
        self.assertIsNone(observe.audio_width(52))        # nch 0: below a pair
        self.assertIsNone(observe.audio_width(1564))      # nch 42: past 40


class TestSight(unittest.TestCase):
    def test_untagged_downstream(self):
        s = observe.sight(eth(BCAST, MASTER, filler_payload(1492)))
        self.assertEqual((s.vlan, s.bcast, s.width, s.kind),
                         (None, True, 40, "filler"))

    def test_inline_tag_wins_and_width_ignores_it(self):
        s = observe.sight(eth(MASTER, BOX, filler_payload(628), vlan=30),
                          aux_vlan=7)
        self.assertEqual(s.vlan, 30)      # the frame's own tag, not aux
        self.assertEqual(s.width, 16)     # untagged-equivalent length
        self.assertFalse(s.bcast)

    def test_aux_vlan_recovered_when_stripped(self):
        s = observe.sight(eth(BCAST, MASTER, filler_payload(1492)), aux_vlan=20)
        self.assertEqual(s.vlan, 20)

    def test_foreign_ethertype_is_not_reac(self):
        ip = BCAST + MASTER + b"\x08\x00" + b"\x00" * 60
        self.assertIsNone(observe.sight(ip))


class TestRoles(unittest.TestCase):
    def feed(self, seg, frame, aux_vlan=None, iface="trunk0"):
        seg.feed(iface, observe.sight(frame, aux_vlan=aux_vlan))

    def test_master_and_box_separate_within_a_vlan(self):
        seg = observe.Segments()
        for _ in range(5):
            self.feed(seg, eth(BCAST, MASTER, filler_payload(1492)), aux_vlan=10)
            self.feed(seg, eth(MASTER, BOX, filler_payload(628)), aux_vlan=10)
        self.assertEqual(seg.streams[("trunk0", 10, observe._mac(MASTER))].role(),
                         "master")
        self.assertEqual(seg.streams[("trunk0", 10, observe._mac(BOX))].role(),
                         "box")

    def test_same_mac_on_two_vlans_is_two_streams(self):
        # The M-5000's ports and a mirror that lost its tags must never merge:
        # the (iface, vlan, src) key is the separation the tool exists for.
        seg = observe.Segments()
        self.feed(seg, eth(BCAST, MASTER, filler_payload(1492)), aux_vlan=10)
        self.feed(seg, eth(BCAST, MASTER, filler_payload(1492)), aux_vlan=20)
        self.assertEqual(len(seg.streams), 2)

    def test_final_only_tick_still_measures(self):
        # --seconds shorter than --interval: no intermediate table ever ticks,
        # the final one must still read the cadence from first frame to now.
        st = observe.Stream()
        s = observe.sight(eth(BCAST, MASTER, filler_payload(1492)))
        for i in range(80):
            st.feed(s, ts=i * 0.000125)
        st.tick(0.01)
        self.assertAlmostEqual(st.pps, 8000.0)

    def test_windowed_pps_reads_the_cadence(self):
        st = observe.Stream()
        st.tick(0.0)
        s = observe.sight(eth(BCAST, MASTER, filler_payload(1492)))
        for _ in range(80):
            st.feed(s)
        st.tick(0.01)  # 80 frames in 10 ms = 8000 pps (96 kHz cadence)
        self.assertAlmostEqual(st.pps, 8000.0)


if __name__ == "__main__":
    unittest.main()
