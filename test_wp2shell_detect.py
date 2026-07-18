#!/usr/bin/env python3
"""Offline unit tests for the version/verdict logic (no network)."""
import unittest
from unittest import mock

from wp2shell_detect import (
    RCE_RANGES,
    SQLI_RANGES,
    Resp,
    _core_asset_version,
    assess,
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


class Fingerprinting(unittest.TestCase):
    def test_csp_wordpress_domain_is_not_a_wordpress_site(self):
        # Regression: a non-WP front (Next.js) whose CSP references a
        # wordpress.* media domain must NOT be flagged as WordPress.
        def fake(url, method="GET", insecure=False):
            if any(s in url for s in ("/wp-json", "/feed", "readme")):
                return Resp(404, "not found", {})
            return Resp(
                200,
                "<html><body>a Next.js site</body></html>",
                {"content-security-policy": "img-src https://wordpress.example.io"},
            )

        with mock.patch("wp2shell_detect._request", side_effect=fake):
            r = assess("https://front.example.io", insecure=False)
        self.assertEqual(r.verdict, "not-wordpress")

    def test_discovers_headless_wordpress_host_from_csp(self):
        def fake(url, method="GET", insecure=False):
            if any(s in url for s in ("/wp-json", "/feed", "readme")):
                return Resp(404, "not found", {})
            return Resp(
                200,
                "<html><body>Next.js</body></html>",
                {"content-security-policy": "img-src https://wordpress.example.io"},
            )

        with mock.patch("wp2shell_detect._request", side_effect=fake):
            r = assess("https://front.example.io", insecure=False)
        self.assertIn("wordpress.example.io", r.discovered)

    def test_discovery_ignores_cross_domain_and_wordpress_org(self):
        # A generator link to wordpress.org and a foreign CDN must NOT be
        # reported as the target's headless back-end.
        def fake(url, method="GET", insecure=False):
            if any(s in url for s in ("/wp-json", "/feed", "readme")):
                return Resp(404, "not found", {})
            body = (
                "<a href='https://wordpress.org/?v=6.9'>"
                "<img src='https://cdn.othercdn.net/wp-content/x.png'>"
            )
            return Resp(200, body, {})

        with mock.patch("wp2shell_detect._request", side_effect=fake):
            r = assess("https://front.example.io", insecure=False)
        self.assertEqual(r.discovered, [])

    def test_core_asset_version_ignores_plugin_assets(self):
        body = (
            "<link href='/wp-includes/css/dist/block-library/style.min.css?ver=6.9.3'>"
            "<script src='/wp-content/plugins/foo/f.js?ver=1.2.3'></script>"
        )
        self.assertEqual(_core_asset_version(body), "6.9.3")

    def test_core_asset_version_none_without_core_asset(self):
        self.assertIsNone(_core_asset_version("<script src='/wp-content/x.js?ver=1.0'>"))


if __name__ == "__main__":
    unittest.main()
