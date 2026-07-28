# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Pau Aliagas <linuxnow@gmail.com>

"""Tests for the REAC rate table: pps = rate / 12, and what happens off nominal.

REAC carries no sample-rate field, so every rate figure in the toolkit is
derived from the packet rate. A frame holds 12 time-samples per channel slot at
every supported rate, which fixes the table at 3675 / 4000 / 8000 pps for
44.1 / 48 / 96 kHz. These tests pin that derivation so no hand-typed constant
can drift away from it again -- the 3000 pps default that used to sit in
reac.cli was a clock-lock-loss measurement, not a rate.
"""
import unittest

from reac.characterize import _RATES
from reac.model import (RATE_PPS, REAC_RATES, SAMPLES_PER_FRAME, pps_for_rate,
                        rate_from_pps)


class TestRateTable(unittest.TestCase):
    def test_pps_is_rate_over_twelve_for_every_rate(self):
        for rate in REAC_RATES:
            with self.subTest(rate=rate):
                self.assertEqual(pps_for_rate(rate), rate / 12)
                self.assertEqual(RATE_PPS[rate], rate / SAMPLES_PER_FRAME)

    def test_table_values(self):
        self.assertEqual(RATE_PPS, {44100: 3675.0, 48000: 4000.0, 96000: 8000.0})

    def test_characterize_shares_the_one_table(self):
        # characterize used to carry its own copy; it must not diverge again
        self.assertIs(_RATES, RATE_PPS)


class TestRateFromPps(unittest.TestCase):
    def test_exact_nominal_resolves(self):
        for rate in REAC_RATES:
            with self.subTest(rate=rate):
                self.assertEqual(rate_from_pps(RATE_PPS[rate]), rate)

    def test_slightly_off_nominal_still_resolves(self):
        # short captures measure a few percent off; 4060 pps is the test fixture
        self.assertEqual(rate_from_pps(4060), 48000)
        self.assertEqual(rate_from_pps(7900), 96000)
        self.assertEqual(rate_from_pps(3700), 44100)

    def test_clock_lock_loss_reading_does_not_resolve(self):
        # the 2026-05-30 rig measured ~3000 pps while both boxes were losing
        # lock: 18 % below 44.1 kHz nominal, so it must not snap to any rate
        self.assertIsNone(rate_from_pps(3000))

    def test_absurd_rates_do_not_resolve(self):
        self.assertIsNone(rate_from_pps(0))
        self.assertIsNone(rate_from_pps(50))
        self.assertIsNone(rate_from_pps(20000))

    def test_tolerance_is_adjustable(self):
        self.assertEqual(rate_from_pps(3000, tolerance=0.25), 44100)


if __name__ == "__main__":
    unittest.main()
