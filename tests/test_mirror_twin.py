# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Pau Aliagas <linuxnow@gmail.com>

"""Tests for mirror-twin dedup: the same frame captured twice.

A capture rig that mirrors BOTH RX and TX of one port sees a transiting frame
twice -- same source MAC, same counter, same payload -- with one copy carrying
2 bytes of the frame's own Ethernet FCS after the C2 EA end marker and the
other not. Every timing figure has to be taken after those copies are gone:
half a mirrored stream's inter-arrivals are near-zero, which drags the median
away from the real cadence, and since REAC has no rate field the frame rate IS
the sample rate.

Measured on a real mirrored S-1608 cold-connect capture, master stream:
166,666 frames -> 83,333 after dedup, median inter-arrival 57.0 us (a nonsense
210 kHz) -> 250.1 us (48.0 kHz). The box's return in the same capture is not
duplicated and comes through untouched, 83,334 -> 83,334.

These tests reproduce both shapes synthetically so CI covers them without the
private corpus: the +2 residue pair, and the equal-length verbatim repeat.
"""
import binascii
import contextlib
import io
import os
import tempfile
import unittest

from reac.analyzer import dedupe_mirror_twins, jitter_stats
from reac.characterize import characterize
from reac.cli import main, modal_pps
from reac.model import (BYTES_PER_CHANNEL, FCS_RESIDUE, PAYLOAD_OVERHEAD,
                        Frame, clean_payload_len)
from reac.parser import parse_tcpdump_text
from reac.pcap import read_pcap, write_pcap

SRC_MASTER = "00:40:ab:c9:cc:03"
SRC_BOX = "00:40:ab:c4:80:41"


def payload(width, seq, marker=0x0e):
    """A clean REAC payload for a `width`-channel frame, counter `seq`."""
    body = bytes([seq & 0xFF, seq >> 8]) + bytes([marker]) * (
        PAYLOAD_OVERHEAD + width * BYTES_PER_CHANNEL - 2)
    assert b"\x88\x19" not in body        # would confuse the tcpdump-text parser
    return body


def with_residue(pay):
    """The mirror twin of `pay`: the same bytes plus its own low-16 FCS, LE."""
    fcs = binascii.crc32(pay) & 0xFFFF
    twin = pay + bytes([fcs & 0xFF, fcs >> 8])
    assert b"\x88\x19" not in twin
    return twin


def frame(ts, src, pay, seq):
    return Frame(ts=ts, src=src, vlan=None, seq=seq, payload_len=len(pay),
                 payload=pay)


class TestCleanPayloadLen(unittest.TestCase):
    def test_strips_exactly_the_two_residue_bytes(self):
        for width in (8, 16, 32, 40):
            clean = PAYLOAD_OVERHEAD + width * BYTES_PER_CHANNEL
            with self.subTest(width=width):
                self.assertEqual(clean_payload_len(clean + FCS_RESIDUE), clean)

    def test_clean_lengths_are_returned_unchanged(self):
        for width in (8, 16, 32, 40):
            clean = PAYLOAD_OVERHEAD + width * BYTES_PER_CHANNEL
            with self.subTest(width=width):
                self.assertEqual(clean_payload_len(clean), clean)

    def test_downstream_1492_and_1494_frames(self):
        # the pair named in FreeREAC/reac-pw#82, in payload terms (frame - 14)
        self.assertEqual(clean_payload_len(1480), 1478)
        self.assertEqual(clean_payload_len(1478), 1478)

    def test_other_offsets_are_not_the_residue_rule(self):
        clean = PAYLOAD_OVERHEAD + 16 * BYTES_PER_CHANNEL
        for off in (1, 3, 4, 35):
            with self.subTest(off=off):
                self.assertEqual(clean_payload_len(clean + off), clean + off)

    def test_short_lengths_untouched(self):
        for n in (0, 2, 39):
            self.assertEqual(clean_payload_len(n), n)


class TestDedupeMirrorTwins(unittest.TestCase):
    def test_residue_twin_is_dropped(self):
        pay = payload(16, 0x1234)
        fs = [frame(0.0, SRC_MASTER, pay, 0x1234),
              frame(0.000004, SRC_MASTER, with_residue(pay), 0x1234)]
        kept = dedupe_mirror_twins(fs)
        self.assertEqual(len(kept), 1)
        self.assertIs(kept[0], fs[0])          # the first copy seen is the one kept

    def test_twin_ordering_does_not_matter(self):
        # the mirror emits the residue copy first about as often as second
        pay = payload(16, 0x1234)
        fs = [frame(0.0, SRC_MASTER, with_residue(pay), 0x1234),
              frame(0.000004, SRC_MASTER, pay, 0x1234)]
        self.assertEqual(len(dedupe_mirror_twins(fs)), 1)

    def test_equal_length_verbatim_repeat_is_dropped(self):
        # the other duplicated-delivery path: a box re-sending a frame as is
        pay = payload(16, 0x1234)
        fs = [frame(0.0, SRC_BOX, pay, 0x1234),
              frame(0.000125, SRC_BOX, pay, 0x1234)]
        self.assertEqual(len(dedupe_mirror_twins(fs)), 1)

    def test_distinct_frames_are_never_dropped(self):
        fs = [frame(i * 0.00025, SRC_MASTER, payload(16, 0x1234 + i), 0x1234 + i)
              for i in range(20)]
        self.assertEqual(dedupe_mirror_twins(fs), fs)

    def test_no_op_on_a_capture_with_no_twin(self):
        # 40 distinct frames from two sources interleaved, none duplicated:
        # dedup must return exactly what it was given, same objects, same order
        fs = []
        for i in range(20):
            fs.append(frame(i * 0.00025, SRC_MASTER, payload(40, 0x100 + i), 0x100 + i))
            fs.append(frame(i * 0.00025 + 6e-5, SRC_BOX, payload(16, 0x200 + i),
                            0x200 + i))
        self.assertEqual(dedupe_mirror_twins(fs), fs)

    def test_dedup_is_per_source(self):
        # two sources whose payloads happen to coincide are not each other's twin
        pay = payload(16, 0x1234)
        fs = [frame(0.0, SRC_MASTER, pay, 0x1234),
              frame(0.00001, SRC_BOX, pay, 0x1234)]
        self.assertEqual(len(dedupe_mirror_twins(fs)), 2)

    def test_a_repeat_after_an_intervening_frame_is_kept(self):
        # only the immediately preceding frame is a twin candidate; a payload
        # that comes back later is a real retransmission, not a mirror copy
        a, b = payload(16, 0x1), payload(16, 0x2)
        fs = [frame(0.0, SRC_MASTER, a, 1), frame(0.00025, SRC_MASTER, b, 2),
              frame(0.0005, SRC_MASTER, a, 1)]
        self.assertEqual(len(dedupe_mirror_twins(fs)), 3)

    def test_frames_without_payload_bytes_are_kept(self):
        fs = [Frame(ts=i * 0.00025, src=SRC_MASTER, vlan=None, seq=i,
                    payload_len=628) for i in range(5)]
        self.assertEqual(dedupe_mirror_twins(fs), fs)

    def test_empty_input(self):
        self.assertEqual(dedupe_mirror_twins([]), [])


class TestMirroredStreamTiming(unittest.TestCase):
    """The reason dedup has to run before anything is measured."""

    @staticmethod
    def mirrored(n=40, spacing=1 / 4000.0, twin_gap=4e-6):
        fs = []
        for i in range(n):
            pay = payload(40, 0x100 + i)
            fs.append(frame(i * spacing, SRC_MASTER, pay, 0x100 + i))
            fs.append(frame(i * spacing + twin_gap, SRC_MASTER,
                            with_residue(pay), 0x100 + i))
        return fs

    def test_mirrored_stream_reads_a_rate_that_was_never_on_the_wire(self):
        fs = self.mirrored()
        self.assertGreater(modal_pps(fs), 4000 * 1.1)

    def test_dedup_restores_the_real_cadence(self):
        kept = dedupe_mirror_twins(self.mirrored())
        self.assertAlmostEqual(modal_pps(kept), 4000.0, delta=1.0)

    def test_dedup_halves_the_frame_count_exactly(self):
        fs = self.mirrored()
        self.assertEqual(len(dedupe_mirror_twins(fs)), len(fs) // 2)

    def test_jitter_no_longer_sees_the_twin_gaps(self):
        kept = dedupe_mirror_twins(self.mirrored())
        j = jitter_stats(kept, nominal_dt=1 / 4000.0)
        self.assertAlmostEqual(j.max_gap_ratio, 1.0, delta=0.01)


def tcpdump_text(frames_in):
    """Payload-only `tcpdump -xx` text for (ts, src, payload) tuples."""
    lines = []
    for ts, src, pay in frames_in:
        lines.append("09:03:%09.6f %s > ff:ff:ff:ff:ff:ff, "
                     "ethertype Unknown (0x8819), length %d:"
                     % (ts, src, len(pay)))
        lines.append("\t0x0000:  " + pay.hex())
    return "\n".join(lines) + "\n"


@contextlib.contextmanager
def capture_file(text):
    fd, path = tempfile.mkstemp(suffix=".txt")
    try:
        with os.fdopen(fd, "w") as fh:
            fh.write(text)
        yield path
    finally:
        os.unlink(path)


def run_cli(text, *argv):
    out = io.StringIO()
    with capture_file(text) as path, contextlib.redirect_stdout(out):
        code = main([path, *argv])
    return code, out.getvalue()


class TestCliOnAMirroredCapture(unittest.TestCase):
    @staticmethod
    def text(n=30, spacing=1 / 4000.0, twin_gap=4e-6, mirror=True):
        rows = []
        for i in range(n):
            pay = payload(40, 0x100 + i)
            rows.append((13.0 + i * spacing, SRC_MASTER, pay))
            if mirror:
                rows.append((13.0 + i * spacing + twin_gap, SRC_MASTER,
                             with_residue(pay)))
        return tcpdump_text(rows)

    def test_mirrored_48k_capture_now_resolves_to_48_khz(self):
        code, out = run_cli(self.text())
        self.assertEqual(code, 0)
        self.assertIn("48 kHz", out)
        self.assertIn("nominal 4000 pps", out)
        self.assertNotIn("RATE UNRESOLVED", out)

    def test_dropped_twins_are_reported_not_silently_swallowed(self):
        _code, out = run_cli(self.text(n=30))
        self.assertIn("mirror twins dropped: 30 of 60", out)
        self.assertIn("both-directions port mirror", out)

    def test_parser_carries_the_payload_bytes_dedup_needs(self):
        frames_parsed = parse_tcpdump_text(self.text(n=2))
        self.assertEqual(len(frames_parsed), 4)
        self.assertTrue(all(f.payload for f in frames_parsed))
        self.assertEqual(len(dedupe_mirror_twins(frames_parsed)), 2)

    def test_unmirrored_capture_is_untouched(self):
        code, out = run_cli(self.text(mirror=False))
        self.assertEqual(code, 0)
        self.assertIn("48 kHz", out)
        self.assertNotIn("mirror twins dropped", out)
        self.assertIn("n=30", out)


def _eth(src, pay):
    def mac(s):
        return bytes.fromhex(s.replace(":", ""))
    return mac("ff:ff:ff:ff:ff:ff") + mac(src) + b"\x88\x19" + pay


class TestPcapAndCharacterize(unittest.TestCase):
    @staticmethod
    def pcap_rows(n=20, spacing=1 / 4000.0, mirror=True):
        rows = []
        for i in range(n):
            pay = payload(40, 0x100 + i)
            rows.append((1.0 + i * spacing, _eth(SRC_MASTER, pay)))
            if mirror:
                rows.append((1.0 + i * spacing + 4e-6,
                             _eth(SRC_MASTER, with_residue(pay))))
        return rows

    @contextlib.contextmanager
    def written(self, rows):
        fd, path = tempfile.mkstemp(suffix=".pcap")
        os.close(fd)
        try:
            write_pcap(path, rows)
            yield path
        finally:
            os.unlink(path)

    def test_read_pcap_carries_the_payload(self):
        with self.written(self.pcap_rows(n=2)) as path:
            frames_read = read_pcap(path)
            self.assertEqual(len(frames_read), 4)
            self.assertEqual(len(dedupe_mirror_twins(frames_read)), 2)

    def test_characterize_reports_the_real_rate_on_a_mirrored_pcap(self):
        with self.written(self.pcap_rows()) as path:
            r = characterize(path)
            self.assertEqual(r.inferred_rate, 48000)
            self.assertEqual(r.n_frames, 20)
            self.assertEqual(r.mirror_twins, 20)
            self.assertEqual(r.duplicated, 0)
            self.assertIn("mirror twins dropped", r.summary)

    def test_characterize_is_a_no_op_on_an_unmirrored_pcap(self):
        with self.written(self.pcap_rows(mirror=False)) as path:
            r = characterize(path)
            self.assertEqual(r.inferred_rate, 48000)
            self.assertEqual(r.n_frames, 20)
            self.assertEqual(r.mirror_twins, 0)
            self.assertNotIn("mirror twins dropped", r.summary)


if __name__ == "__main__":
    unittest.main()
