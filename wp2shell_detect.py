#!/usr/bin/env python3
"""
wp2shell-detect — blackbox, non-intrusive detector for wp2shell.

wp2shell (CVE-2026-63030 + CVE-2026-60137, disclosed 2026-07-17) is a
pre-authentication RCE chain in WordPress *core*:

  - CVE-2026-63030: a route-confusion bug in the REST batch endpoint
    (/wp-json/batch/v1) desynchronises request validation from dispatch.
  - CVE-2026-60137: a SQL injection in WP_Query's author__not_in handling,
    reachable pre-auth through that route confusion.

This tool DETECTS exposure. It does NOT exploit anything. It only:

  1. fingerprints the WordPress core version from public, read-only sources
     (generator meta tag, RSS/Atom feed, readme.html, the /wp-json/ index);
  2. compares that version against the known-vulnerable ranges;
  3. checks — with a benign OPTIONS request — whether the REST batch route is
     reachable (i.e. whether an edge mitigation is in place).

No request here triggers the vulnerability. Every request is a normal read a
crawler could make. Use it only on assets you own or are mandated to assess.

Zero third-party dependencies (standard library only). Python 3.8+.

    ./wp2shell_detect.py https://example.com
    ./wp2shell_detect.py --json https://example.com
    ./wp2shell_detect.py --targets hosts.txt

Author: own2pwn <contact@own2pwn.fr> — https://own2pwn.fr
Writeup: https://own2pwn.fr/articles/appsec/wp2shell-wordpress-rce
License: MIT
"""

from __future__ import annotations

import argparse
import json
import re
import ssl
import sys
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass, field
from typing import Optional

USER_AGENT = "wp2shell-detect/1.0 (+https://own2pwn.fr)"
TIMEOUT = 12

# --- Vulnerable version ranges (inclusive), per the disclosure ---------------
# Full pre-auth RCE chain:
RCE_RANGES = [((6, 9, 0), (6, 9, 4)), ((7, 0, 0), (7, 0, 1))]
# SQL injection half only (no RCE on 6.8.x):
SQLI_RANGES = [((6, 8, 0), (6, 8, 5))]
# Fixed in: 6.8.6 / 6.9.5 / 7.0.2 and later.

Version = tuple  # (major, minor, patch)


# -----------------------------------------------------------------------------
# HTTP helper (read-only GET/OPTIONS, no body ever sent)
# -----------------------------------------------------------------------------
@dataclass
class Resp:
    status: int
    body: str
    headers: dict


def _request(url: str, method: str = "GET", insecure: bool = False) -> Optional[Resp]:
    ctx = ssl.create_default_context()
    if insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, method=method, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT, context=ctx) as r:
            raw = r.read(262144)  # cap the body: we only need headers/markers
            return Resp(r.status, raw.decode("utf-8", "replace"), dict(r.headers))
    except urllib.error.HTTPError as e:
        raw = b""
        try:
            raw = e.read(262144)
        except Exception:
            pass
        return Resp(e.code, raw.decode("utf-8", "replace"), dict(e.headers or {}))
    except Exception:
        return None


# -----------------------------------------------------------------------------
# Version fingerprinting — several independent public sources
# -----------------------------------------------------------------------------
_VER_RE = r"(\d+\.\d+(?:\.\d+)?)"


def parse_version(v: str) -> Optional[Version]:
    """'6.9.3' or '7.0' -> (6, 9, 3) / (7, 0, 0). Strict: the whole string must
    be a clean numeric X.Y(.Z) version. Anything else ('6.9.x', '7.1-beta2')
    returns None so we never flag on a value we cannot trust."""
    m = re.match(r"^(\d+)\.(\d+)(?:\.(\d+))?$", v.strip())
    if not m:
        return None
    return (int(m.group(1)), int(m.group(2)), int(m.group(3) or 0))


def fingerprint_version(base: str, insecure: bool) -> tuple[Optional[str], list[str]]:
    """Return (version_string, [source, ...]) from read-only public endpoints."""
    found: dict[str, str] = {}

    # 1) generator meta tag on the homepage
    home = _request(base + "/", insecure=insecure)
    if home and home.status < 400:
        m = re.search(
            r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']WordPress\s+'
            + _VER_RE,
            home.body,
            re.I,
        )
        if m:
            found["generator meta tag"] = m.group(1)
        # WordPress emits a stylesheet/script ?ver= too, but that tracks assets,
        # not core, so we deliberately do not trust it.

    # 2) RSS feed <generator>https://wordpress.org/?v=X.Y.Z</generator>
    feed = _request(base + "/feed/", insecure=insecure) or _request(
        base + "/?feed=rss2", insecure=insecure
    )
    if feed and feed.status < 400:
        m = re.search(r"wordpress\.org/\?v=" + _VER_RE, feed.body, re.I)
        if m:
            found["RSS feed generator"] = m.group(1)

    # 3) readme.html "Version X.Y.Z"
    readme = _request(base + "/readme.html", insecure=insecure)
    if readme and readme.status == 200 and "WordPress" in readme.body:
        m = re.search(r"Version\s+" + _VER_RE, readme.body, re.I)
        if m:
            found["readme.html"] = m.group(1)

    # 4) /wp-json/ index sometimes carries no version, but the Link header and
    #    body confirm REST is exposed; some setups leak a version in 'description'
    api = _request(base + "/wp-json/", insecure=insecure)
    if api and api.status == 200:
        m = re.search(r'"description"\s*:\s*"[^"]*?' + _VER_RE, api.body)
        if m:
            found["wp-json index"] = m.group(1)

    if not found:
        return None, []
    # If multiple sources agree, great; if they disagree, keep the highest
    # (most conservative: a higher version is less likely to be a false positive
    # for a vulnerable range, and readme is often stale on updated installs).
    best = max(found.values(), key=lambda v: parse_version(v) or (0, 0, 0))
    sources = [f"{src}={ver}" for src, ver in found.items()]
    return best, sources


# -----------------------------------------------------------------------------
# REST batch endpoint reachability (benign OPTIONS, never POST)
# -----------------------------------------------------------------------------
def batch_endpoint_reachable(base: str, insecure: bool) -> Optional[bool]:
    """True if /wp-json/batch/v1 is reachable, False if blocked/absent,
    None if REST itself is unreachable. Uses OPTIONS: it returns the route
    schema without ever invoking the handler (no exploitation)."""
    # REST must be up at all first.
    idx = _request(base + "/wp-json/", insecure=insecure)
    if not (idx and idx.status == 200):
        return None
    for url in (base + "/wp-json/batch/v1", base + "/?rest_route=/batch/v1"):
        r = _request(url, method="OPTIONS", insecure=insecure)
        if not r:
            continue
        # 200 with an Allow/endpoints payload => route exists and is reachable.
        if r.status == 200 and ("POST" in r.headers.get("Allow", "") or '"methods"' in r.body):
            return True
        # 403/401 => an edge control is blocking it (good — mitigation present).
        if r.status in (401, 403):
            return False
    return False


# -----------------------------------------------------------------------------
# Verdict
# -----------------------------------------------------------------------------
def in_ranges(v: Version, ranges) -> bool:
    return any(lo <= v <= hi for lo, hi in ranges)


@dataclass
class Result:
    target: str
    is_wordpress: bool = False
    version: Optional[str] = None
    version_sources: list = field(default_factory=list)
    batch_reachable: Optional[bool] = None
    verdict: str = "unknown"
    cves: list = field(default_factory=list)
    detail: str = ""


def assess(target: str, insecure: bool) -> Result:
    base = target.rstrip("/")
    if not base.startswith(("http://", "https://")):
        base = "https://" + base
    res = Result(target=base)

    home = _request(base + "/", insecure=insecure)
    if home is None:
        res.verdict = "unreachable"
        res.detail = "host did not respond"
        return res

    # Body + Link header only. Scanning ALL headers for "wordpress" caused false
    # positives: a CSP that references a wordpress.* media domain (headless setups)
    # made a non-WordPress front look like WordPress.
    link = home.headers.get("Link") or home.headers.get("link") or ""
    blob = (home.body[:8192] + " " + link).lower()
    res.is_wordpress = ("wp-content" in blob or "wp-includes" in blob
                        or "wp-json" in blob or "wordpress" in blob)
    if not res.is_wordpress:
        # Fallback: a genuine WP REST index (200 + namespaces), not just any
        # response — a 404 page must not count as "WordPress".
        api = _request(base + "/wp-json/", insecure=insecure)
        if api and api.status == 200 and ('"namespaces"' in api.body or '"wp/v2"' in api.body):
            res.is_wordpress = True
    if not res.is_wordpress:
        res.verdict = "not-wordpress"
        res.detail = "no WordPress fingerprint on the homepage"
        return res

    version, sources = fingerprint_version(base, insecure)
    res.version, res.version_sources = version, sources
    res.batch_reachable = batch_endpoint_reachable(base, insecure)

    if version is None:
        res.verdict = "unknown-version"
        res.detail = (
            "WordPress confirmed but core version is hidden. Blackbox detection "
            "cannot confirm wp2shell without exploiting; patch to the latest 6.8.6/"
            "6.9.5/7.0.2+ and block /wp-json/batch/v1 to be safe."
        )
        return res

    v = parse_version(version)
    if v is None:
        res.verdict = "unknown-version"
        res.detail = f"could not parse version {version!r}"
        return res

    if in_ranges(v, RCE_RANGES):
        res.verdict = "vulnerable-rce"
        res.cves = ["CVE-2026-63030", "CVE-2026-60137"]
        res.detail = (
            f"WordPress {version} is in the wp2shell pre-auth RCE range. "
            + ("REST batch endpoint reachable — no edge mitigation."
               if res.batch_reachable else
               "Batch endpoint appears blocked/absent, but patch anyway.")
        )
    elif in_ranges(v, SQLI_RANGES):
        res.verdict = "vulnerable-sqli"
        res.cves = ["CVE-2026-60137"]
        res.detail = f"WordPress {version} is affected by the SQLi half only (no RCE on 6.8.x)."
    else:
        res.verdict = "likely-patched"
        res.detail = f"WordPress {version} is outside every vulnerable range."
    return res


# -----------------------------------------------------------------------------
# CLI
# -----------------------------------------------------------------------------
_LABEL = {
    "vulnerable-rce": "VULNERABLE (pre-auth RCE)",
    "vulnerable-sqli": "VULNERABLE (SQL injection only)",
    "likely-patched": "likely patched",
    "unknown-version": "WordPress, version hidden",
    "not-wordpress": "not WordPress",
    "unreachable": "unreachable",
    "unknown": "unknown",
}


def print_human(r: Result) -> None:
    tag = _LABEL.get(r.verdict, r.verdict)
    mark = {
        "vulnerable-rce": "[!!]",
        "vulnerable-sqli": "[! ]",
        "likely-patched": "[ok]",
    }.get(r.verdict, "[??]")
    print(f"{mark} {r.target}  ->  {tag}")
    if r.version:
        print(f"      version : {r.version}  ({', '.join(r.version_sources)})")
    if r.batch_reachable is not None:
        print(f"      batch   : {'reachable' if r.batch_reachable else 'blocked/absent'}"
              f"  (/wp-json/batch/v1)")
    if r.cves:
        print(f"      cves    : {', '.join(r.cves)}")
    if r.detail:
        print(f"      note    : {r.detail}")


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Blackbox, non-intrusive detector for wp2shell (CVE-2026-63030).",
        epilog="Detection only. Never run against systems you are not authorised to assess.",
    )
    ap.add_argument("targets", nargs="*", help="target URL(s) or host(s)")
    ap.add_argument("--targets", dest="file", help="file with one target per line")
    ap.add_argument("--json", action="store_true", help="emit JSON (one object per line)")
    ap.add_argument("--insecure", action="store_true", help="skip TLS verification")
    args = ap.parse_args()

    targets = list(args.targets)
    if args.file:
        with open(args.file, encoding="utf-8") as fh:
            targets += [ln.strip() for ln in fh if ln.strip() and not ln.startswith("#")]
    if not targets:
        ap.error("no targets given")

    exit_code = 0
    for t in targets:
        r = assess(t, insecure=args.insecure)
        if args.json:
            print(json.dumps(asdict(r)))
        else:
            print_human(r)
        if r.verdict in ("vulnerable-rce", "vulnerable-sqli"):
            exit_code = 2
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
