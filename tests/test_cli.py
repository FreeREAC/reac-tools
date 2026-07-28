# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Pau Aliagas <linuxnow@gmail.com>

"""End-to-end tests for `python3 -m reac.cli`, centred on the nominal frame rate.

The jitter ratio the CLI prints is only meaningful against the right nominal
frame interval. The CLI used to default that to 3000 pps -- a figure measured
while both stageboxes were losing clock lock -- which scaled every ratio on a
48 kHz stream by ~25 %. It now measures each stream's own rate and snaps it to
the nearest REAC rate, refuses to guess when nothing is near, and still takes
an explicit --rate / --fps.
"""
import contextlib
import io
import os
import tempfile
import unittest

from reac.cli import main, modal_pps
from reac.parser import parse_tcpdump_text

SRC = "00:40:ab:c9:91:9c"


def tcpdump_text(spacing, n=9, seq0=0xfd7e, src=SRC, t0=13.0):
    """Synthesize payload-only `tcpdump -xx` text for one evenly spaced stream."""
    lines = []
    for i in range(n):
        seq = (seq0 + i) & 0xFFFF
        lines.append("09:03:%09.6f %s > ff:ff:ff:ff:ff:ff, "
                     "ethertype Unknown (0x8819), length 1496:"
                     % (t0 + i * spacing, src))
        lines.append("\t0x0000:  %02x%02x 0000 000e 000e 000e 000e 000e 000e"
                     % (seq & 0xFF, seq >> 8))
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


def run(text, *argv):
    """Run the CLI over a synthetic capture; return (exit_code, stdout)."""
    out = io.StringIO()
    with capture_file(text) as path, contextlib.redirect_stdout(out):
        code = main([path, *argv])
    return code, out.getvalue()


class TestNominalRateInference(unittest.TestCase):
    def test_48k_stream_infers_4000_pps_with_no_flags(self):
        code, out = run(tcpdump_text(1 / 4000.0))
        self.assertEqual(code, 0)
        self.assertIn("48 kHz", out)
        self.assertIn("nominal 4000 pps", out)
        self.assertIn("(inferred)", out)

    def test_96k_stream_infers_8000_pps(self):
        code, out = run(tcpdump_text(1 / 8000.0))
        self.assertEqual(code, 0)
        self.assertIn("96 kHz", out)
        self.assertIn("nominal 8000 pps", out)

    def test_44k1_stream_infers_3675_pps(self):
        code, out = run(tcpdump_text(1 / 3675.0))
        self.assertEqual(code, 0)
        self.assertIn("44.1 kHz", out)
        self.assertIn("nominal 3675 pps", out)

    def test_evenly_spaced_48k_stream_reads_as_ratio_one(self):
        # the regression the old 3000 default caused: an evenly spaced 48 kHz
        # stream is exactly nominal, so its worst gap must be 1.0x, not 0.7x
        _code, out = run(tcpdump_text(1 / 4000.0))
        self.assertIn("(1.0x nominal)", out)
        self.assertIn("-> clean", out)


class TestOffNominalStream(unittest.TestCase):
    TEXT = tcpdump_text(1 / 3000.0)

    def test_off_nominal_stream_is_not_snapped_to_a_rate(self):
        code, out = run(self.TEXT)
        self.assertEqual(code, 3)
        self.assertIn("RATE UNRESOLVED", out)
        self.assertIn("matches no REAC rate", out)

    def test_off_nominal_stream_withholds_the_jitter_ratio(self):
        _code, out = run(self.TEXT)
        self.assertNotIn("x nominal", out)
        self.assertNotIn("-> clean", out)
        # absolute timing is still reported; only the derived ratio is withheld
        self.assertIn("mean_dt=", out)
        self.assertIn("max_gap=", out)

    def test_explicit_rate_resolves_an_off_nominal_stream(self):
        code, out = run(self.TEXT, "--rate", "48000")
        self.assertEqual(code, 0)
        self.assertIn("nominal 4000 pps (--rate 48000)", out)
        self.assertIn("x nominal", out)


class TestExplicitFlags(unittest.TestCase):
    def test_fps_overrides_inference(self):
        code, out = run(tcpdump_text(1 / 4000.0), "--fps", "3000")
        self.assertEqual(code, 0)
        self.assertIn("nominal 3000 pps (--fps)", out)
        # 250us gaps against a 333us nominal: the ~25 % scaling, now explicit
        self.assertIn("(0.8x nominal)", out)

    def test_forced_rate_that_contradicts_the_stream_warns(self):
        # the old default's exact failure mode: 3000 pps forced onto a 48 kHz
        # stream. Still allowed -- the operator may know better -- but flagged
        _code, out = run(tcpdump_text(1 / 4000.0), "--fps", "3000")
        self.assertIn("WARNING", out)
        self.assertIn("4000 pps = 48 kHz", out)

    def test_forced_rate_matching_the_stream_does_not_warn(self):
        _code, out = run(tcpdump_text(1 / 4000.0), "--rate", "48000")
        self.assertNotIn("WARNING", out)

    def test_rate_only_accepts_reac_rates(self):
        with self.assertRaises(SystemExit):
            with contextlib.redirect_stdout(io.StringIO()), \
                 contextlib.redirect_stderr(io.StringIO()):
                main(["/dev/null", "--rate", "88200"])

    def test_rate_and_fps_are_mutually_exclusive(self):
        with self.assertRaises(SystemExit):
            with contextlib.redirect_stdout(io.StringIO()), \
                 contextlib.redirect_stderr(io.StringIO()):
                main(["/dev/null", "--rate", "48000", "--fps", "4000"])

    def test_non_positive_fps_rejected(self):
        with self.assertRaises(SystemExit):
            with contextlib.redirect_stdout(io.StringIO()), \
                 contextlib.redirect_stderr(io.StringIO()):
                main(["/dev/null", "--fps", "0"])


class TestFaultReporting(unittest.TestCase):
    def test_jitter_burst_flagged_against_the_inferred_rate(self):
        # seven 250us gaps plus one 2.5ms stall. The stall drags a span-averaged
        # rate down to ~1900 pps (which would resolve to nothing); the median
        # spacing still reads 4000, so the burst is measured against 48 kHz.
        text = tcpdump_text(1 / 4000.0, n=5)
        tail = tcpdump_text(1 / 4000.0, n=4, seq0=0xfd83, t0=13.0035)
        code, out = run(text + tail)
        self.assertEqual(code, 0)
        self.assertIn("nominal 4000 pps", out)
        self.assertIn("JITTER BURST", out)

    def test_modal_rate_survives_a_stall(self):
        frames = parse_tcpdump_text(tcpdump_text(1 / 4000.0, n=5)
                                    + tcpdump_text(1 / 4000.0, n=4,
                                                   seq0=0xfd83, t0=13.0035))
        self.assertAlmostEqual(modal_pps(frames), 4000, delta=20)

    def test_empty_capture_reports_nothing_parsed(self):
        code, _out = run("")
        self.assertEqual(code, 1)


if __name__ == "__main__":
    unittest.main()
