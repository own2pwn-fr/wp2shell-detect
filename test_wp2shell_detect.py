#!/usr/bin/env python3
"""Offline unit tests for the version/verdict logic (no network)."""
import unittest

from wp2shell_detect import (
    RCE_RANGES,
    SQLI_RANGES,
    in_ranges,
    parse_version,
)


class ParseVersion(unittest.TestCase):
    def test_three_segments(self):
        self.assertEqual(parse_version("6.9.3"), (6, 9, 3))

    def test_two_segments_pads_patch(self):
        self.assertEqual(parse_version("7.0"), (7, 0, 0))

    def test_non_numeric_segment_is_none(self):
        self.assertIsNone(parse_version("6.9.x"))

    def test_suffix_rejected(self):
        # strict: a beta/suffix string is not trusted as a clean version
        self.assertIsNone(parse_version("7.1-beta2"))


class Verdict(unittest.TestCase):
    def rce(self, v):
        return in_ranges(parse_version(v), RCE_RANGES)

    def sqli(self, v):
        return in_ranges(parse_version(v), SQLI_RANGES)

    def test_rce_range(self):
        for v in ("6.9.0", "6.9.4", "7.0.0", "7.0.1"):
            self.assertTrue(self.rce(v), v)

    def test_fixed_versions_not_rce(self):
        for v in ("6.9.5", "7.0.2", "6.8.6", "7.1.0"):
            self.assertFalse(self.rce(v), v)

    def test_sqli_only_range(self):
        for v in ("6.8.0", "6.8.5"):
            self.assertTrue(self.sqli(v), v)
            self.assertFalse(self.rce(v), v)

    def test_old_versions_clean(self):
        for v in ("6.7.0", "5.9.0"):
            self.assertFalse(self.rce(v), v)
            self.assertFalse(self.sqli(v), v)


if __name__ == "__main__":
    unittest.main()
