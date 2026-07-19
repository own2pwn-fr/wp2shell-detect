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

  1. fingerprints the WordPress core version from many public, read-only
     sources (generator meta, RSS feed, core asset ?ver=, OPML, login page,
     readme.html, version.php, the /wp-json/ index);
  2. compares that version against the known-vulnerable ranges;
  3. checks — with a benign OPTIONS request and the REST index — whether the
     batch route is reachable (i.e. whether an edge mitigation is in place);
  4. when the target isn't WordPress itself, discovers headless WordPress
     back-ends it references (CSP / Link header / asset URLs) so you can point
     the scan at the right host.

No request here triggers the vulnerability. Every request is a normal read a
crawler could make. Use it only on assets you own or are mandated to assess.

Zero third-party dependencies (standard library only). Python 3.8+.

    ./wp2shell_detect.py https://example.com
    ./wp2shell_detect.py --json https://example.com
    ./wp2shell_detect.py --discover https://front.example.com   # follow headless WP
    ./wp2shell_detect.py --targets hosts.txt --workers 16

Author: own2pwn <contact@own2pwn.fr> — https://own2pwn.fr
Writeup: https://own2pwn.fr/articles/appsec/wp2shell-wordpress-rce
License: MIT
"""

from __future__ import annotations

import argparse
import gzip
import json
import re
import ssl
import sys
import time
import zlib
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from typing import Optional
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit, urlunsplit
import urllib.request

__version__ = "1.0.0"

# Tunables (overridable via CLI / module state).
USER_AGENT = f"Mozilla/5.0 (X11; Linux x86_64) wp2shell-detect/{__version__} (+https://own2pwn.fr)"
TIMEOUT = 12
RETRIES = 2
MAX_BODY = 512_000  # cap read per response

# --- Vulnerable version ranges (inclusive), per the disclosure ---------------
RCE_RANGES = [((6, 9, 0), (6, 9, 4)), ((7, 0, 0), (7, 0, 1))]  # full pre-auth RCE
SQLI_RANGES = [((6, 8, 0), (6, 8, 5))]  # SQL injection half only (no RCE on 6.8.x)
# Fixed in: 6.8.6 / 6.9.5 / 7.0.2 and later.

Version = tuple  # (major, minor, patch)

_VER = r"(\d+\.\d+(?:\.\d+)?)"


# -----------------------------------------------------------------------------
# HTTP helper (read-only GET/OPTIONS, never a body; retries; gzip; redirects)
# -----------------------------------------------------------------------------
@dataclass
class Resp:
    status: int
    body: str
    headers: dict
    url: str = ""


def _decode_body(raw: bytes, encoding: str) -> str:
    enc = (encoding or "").lower()
    try:
        if "gzip" in enc:
            raw = gzip.decompress(raw)
        elif "deflate" in enc:
            try:
                raw = zlib.decompress(raw)
            except zlib.error:
                raw = zlib.decompress(raw, -zlib.MAX_WBITS)
    except Exception:
        pass
    return raw.decode("utf-8", "replace")


def _norm_headers(msg) -> dict:
    """Lowercased header dict, duplicates joined (Link/CSP may repeat)."""
    out: dict = {}
    for k, v in msg.items():
        lk = k.lower()
        out[lk] = f"{out[lk]}, {v}" if lk in out else v
    return out


def _request(url: str, method: str = "GET", insecure: bool = False) -> Optional[Resp]:
    ctx = ssl.create_default_context()
    if insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    for attempt in range(RETRIES + 1):
        req = urllib.request.Request(
            url,
            method=method,
            headers={
                "User-Agent": USER_AGENT,
                "Accept": "*/*",
                "Accept-Encoding": "gzip, deflate",
                "Accept-Language": "en-US,en;q=0.8",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT, context=ctx) as r:
                raw = r.read(MAX_BODY)
                headers = _norm_headers(r.headers)
                body = _decode_body(raw, headers.get("content-encoding", ""))
                return Resp(r.status, body, headers, r.geturl())
        except HTTPError as e:  # 4xx/5xx is a real answer, not a transport error
            raw = b""
            try:
                raw = e.read(MAX_BODY)
            except Exception:
                pass
            headers = _norm_headers(e.headers) if e.headers else {}
            body = _decode_body(raw, headers.get("content-encoding", ""))
            return Resp(e.code, body, headers, url)
        except (URLError, TimeoutError, ssl.SSLError, ConnectionError, OSError):
            if attempt < RETRIES:
                time.sleep(0.4 * (attempt + 1))
                continue
            return None
        except Exception:
            return None
    return None


def _fetch_home(base: str, insecure: bool) -> Optional[Resp]:
    """Fetch the homepage; fall back https->http; follow a cross-host redirect."""
    r = _request(base + "/", insecure=insecure)
    if r is None and base.startswith("https://"):
        r = _request("http://" + base[len("https://") :] + "/", insecure=insecure)
    return r


# -----------------------------------------------------------------------------
# Version parsing
# -----------------------------------------------------------------------------
def parse_version(v: str) -> Optional[Version]:
    """'6.9.3' or '7.0' -> (6, 9, 3) / (7, 0, 0). Strict: the whole string must
    be a clean numeric X.Y(.Z) version. Anything else ('6.9.x', '7.1-beta2')
    returns None so we never flag on a value we cannot trust."""
    m = re.match(r"^(\d+)\.(\d+)(?:\.(\d+))?$", v.strip())
    if not m:
        return None
    return (int(m.group(1)), int(m.group(2)), int(m.group(3) or 0))


def _core_asset_version(body: str) -> Optional[str]:
    """Version from a CORE asset query string. Only /wp-includes/ and /wp-admin/
    assets track core; /wp-content/ assets (plugins/themes) have their own
    versions and are deliberately ignored."""
    versions = re.findall(
        r"/wp-(?:includes|admin)/[^\"'\s>]*?[?&]ver=" + _VER, body, re.I
    )
    if not versions:
        return None
    # Core assets all share the core version; take the most frequent, then highest.
    best = None
    for v in versions:
        pv = parse_version(v)
        if pv and (best is None or pv > parse_version(best)):
            best = v
    return best


# -----------------------------------------------------------------------------
# Version fingerprinting — many independent public sources, tiered
# -----------------------------------------------------------------------------
def fingerprint_version(
    base: str, insecure: bool, home: Optional[Resp] = None
) -> tuple[Optional[str], list[str]]:
    """Return (version_string, [source, ...]) from read-only public endpoints."""
    found: dict[str, str] = {}
    if home is None:
        home = _fetch_home(base, insecure)

    def add(source: str, version: Optional[str]) -> None:
        if version and parse_version(version):
            found[source] = version

    # Tier 1 — from the already-fetched homepage.
    if home and home.status < 400:
        m = re.search(
            r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']WordPress\s+' + _VER,
            home.body,
            re.I,
        )
        add("generator meta tag", m.group(1) if m else None)
        add("core asset ?ver=", _core_asset_version(home.body))

    # Tier 2 — cheap dedicated endpoints.
    feed = _request(base + "/feed/", insecure=insecure) or _request(
        base + "/?feed=rss2", insecure=insecure
    )
    if feed and feed.status < 400:
        m = re.search(r"wordpress\.org/\?v=" + _VER, feed.body, re.I)
        add("RSS feed generator", m.group(1) if m else None)

    readme = _request(base + "/readme.html", insecure=insecure)
    if readme and readme.status == 200 and "WordPress" in readme.body:
        m = re.search(r"Version\s+" + _VER, readme.body, re.I)
        add("readme.html", m.group(1) if m else None)

    api = _request(base + "/wp-json/", insecure=insecure)
    if api and api.status == 200:
        m = re.search(r'"description"\s*:\s*"[^"]*?' + _VER, api.body)
        add("wp-json index", m.group(1) if m else None)

    # Tier 3 — fallbacks for hardened installs (generator stripped). Only if we
    # still have nothing, to keep the request count low on the common path.
    if not found:
        opml = _request(base + "/wp-links-opml.php", insecure=insecure)
        if opml and opml.status == 200:
            m = re.search(r"WordPress/" + _VER, opml.body, re.I)
            add("wp-links-opml.php", m.group(1) if m else None)

        login = _request(base + "/wp-login.php", insecure=insecure)
        if login and login.status in (200, 503) and "login" in login.body.lower():
            add("wp-login.php asset ?ver=", _core_asset_version(login.body))

        vphp = _request(base + "/wp-includes/version.php", insecure=insecure)
        if vphp and vphp.status == 200 and "$wp_version" in vphp.body:
            m = re.search(r"\$wp_version\s*=\s*'" + _VER, vphp.body)
            add("wp-includes/version.php", m.group(1) if m else None)

    if not found:
        return None, []
    # Prefer the highest parsed version (readme is often stale on updated installs).
    best_src = max(found, key=lambda s: parse_version(found[s]) or (0, 0, 0))
    sources = [f"{src}={ver}" for src, ver in found.items()]
    return found[best_src], sources


# -----------------------------------------------------------------------------
# WordPress fingerprint + headless-host discovery
# -----------------------------------------------------------------------------
def looks_like_wordpress(home: Optional[Resp], base: str, insecure: bool) -> bool:
    if home:
        link = home.headers.get("link", "")
        blob = (home.body[:16_384] + " " + link).lower()
        if any(m in blob for m in ("wp-content", "wp-includes", "wp-json", "wordpress")):
            return True
        if "api.w.org" in link.lower():  # REST discovery Link rel
            return True
    api = _request(base + "/wp-json/", insecure=insecure)
    if api and api.status == 200 and ('"namespaces"' in api.body or '"routes"' in api.body):
        return True
    return False


# WordPress.org project infrastructure — never a target's own back-end.
_WP_INFRA = {"wordpress.org", "w.org", "api.w.org", "s.w.org", "ps.w.org", "wp.org"}


def discover_wp_hosts(home: Optional[Resp], base: str) -> list[str]:
    """WordPress back-ends referenced by a non-WP front: CSP, Link header, and
    absolute wp-content/wp-includes/wp-json URLs in the body. Restricted to the
    target's own registrable domain (a headless WP back-end is virtually always
    a sibling host), which also filters out wordpress.org generator links, CDNs
    and Gravatar."""
    if not home:
        return []
    haystack = " ".join(
        [
            home.body[:65_536],
            home.headers.get("content-security-policy", ""),
            home.headers.get("link", ""),
        ]
    )
    self_host = (urlsplit(base).hostname or "").lower()
    labels = self_host.split(".")
    self_domain = ".".join(labels[-2:]) if len(labels) >= 2 else self_host

    def keep(h: str) -> bool:
        return (
            bool(h)
            and h != self_host
            and h not in _WP_INFRA
            and (h == self_domain or h.endswith("." + self_domain))
        )

    hosts: list[str] = []
    patterns = (
        r"https?://([a-z0-9.-]+)(?::\d+)?/wp-(?:content|includes|json)",
        r"https?://((?:wordpress|wp|cms)\.[a-z0-9.-]+)",  # named WP subdomains
    )
    for pat in patterns:
        for m in re.finditer(pat, haystack, re.I):
            h = m.group(1).lower()
            if keep(h) and h not in hosts:
                hosts.append(h)
    return hosts


# -----------------------------------------------------------------------------
# Batch endpoint reachability (benign, never POST)
# -----------------------------------------------------------------------------
def batch_endpoint_reachable(base: str, insecure: bool) -> Optional[bool]:
    """True reachable, False blocked/absent, None if REST itself is unreachable."""
    idx = _request(base + "/wp-json/", insecure=insecure)
    if not (idx and idx.status == 200):
        return None
    if "batch/v1" in idx.body or "batch\\/v1" in idx.body:
        return True
    for url in (base + "/wp-json/batch/v1", base + "/?rest_route=/batch/v1"):
        r = _request(url, method="OPTIONS", insecure=insecure)
        if not r:
            continue
        allow = r.headers.get("allow", "")
        if r.status == 200 and ("POST" in allow.upper() or '"methods"' in r.body):
            return True
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
    confidence: str = "n/a"
    batch_reachable: Optional[bool] = None
    verdict: str = "unknown"
    cves: list = field(default_factory=list)
    discovered: list = field(default_factory=list)
    detail: str = ""


def normalize_base(target: str) -> str:
    raw = target.strip()
    if not raw:
        return raw
    if not re.match(r"^https?://", raw, re.I):
        raw = "https://" + raw
    parts = urlsplit(raw)
    scheme = parts.scheme.lower() or "https"
    netloc = parts.netloc
    return urlunsplit((scheme, netloc, "", "", ""))  # origin only


def assess(target: str, insecure: bool = False) -> Result:
    base = normalize_base(target)
    res = Result(target=base)

    home = _fetch_home(base, insecure)
    if home is None:
        res.verdict = "unreachable"
        res.detail = "host did not respond"
        return res

    # Follow a cross-host redirect (example.com -> www.example.com).
    if home.url:
        final_host = urlsplit(home.url).hostname
        if final_host and final_host != urlsplit(base).hostname:
            base = normalize_base(home.url)
            res.target = base

    res.is_wordpress = looks_like_wordpress(home, base, insecure)
    res.discovered = discover_wp_hosts(home, base)

    if not res.is_wordpress:
        res.verdict = "not-wordpress"
        res.detail = "no WordPress fingerprint on the homepage"
        if res.discovered:
            res.detail += f"; references WordPress on: {', '.join(res.discovered)}"
        return res

    version, sources = fingerprint_version(base, insecure, home)
    res.version, res.version_sources = version, sources
    res.confidence = "high" if len(sources) >= 2 else ("medium" if sources else "n/a")
    res.batch_reachable = batch_endpoint_reachable(base, insecure)

    if version is None:
        res.verdict = "unknown-version"
        res.detail = (
            "WordPress confirmed but core version is hidden. Blackbox detection "
            "cannot confirm wp2shell without exploiting; patch to the latest "
            "6.8.6/6.9.5/7.0.2+ and block /wp-json/batch/v1 to be safe."
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
            + (
                "REST batch endpoint reachable — no edge mitigation."
                if res.batch_reachable
                else "Batch endpoint appears blocked/absent, but patch anyway."
            )
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
_MARK = {
    "vulnerable-rce": "[!!]",
    "vulnerable-sqli": "[! ]",
    "likely-patched": "[ok]",
}


def print_human(r: Result) -> None:
    tag = _LABEL.get(r.verdict, r.verdict)
    print(f"{_MARK.get(r.verdict, '[??]')} {r.target}  ->  {tag}")
    if r.version:
        print(f"      version : {r.version}  ({', '.join(r.version_sources)})  [{r.confidence}]")
    if r.batch_reachable is not None:
        print(
            f"      batch   : {'reachable' if r.batch_reachable else 'blocked/absent'}"
            "  (/wp-json/batch/v1)"
        )
    if r.cves:
        print(f"      cves    : {', '.join(r.cves)}")
    if r.discovered:
        print(f"      wp hosts: {', '.join(r.discovered)}")
    if r.detail:
        print(f"      note    : {r.detail}")


def main() -> int:
    global TIMEOUT, USER_AGENT
    ap = argparse.ArgumentParser(
        description="Blackbox, non-intrusive detector for wp2shell (CVE-2026-63030).",
        epilog="Detection only. Never run against systems you are not authorised to assess.",
    )
    ap.add_argument("targets", nargs="*", help="target URL(s) or host(s)")
    ap.add_argument("--targets", dest="file", help="file with one target per line")
    ap.add_argument("--json", action="store_true", help="emit JSON (one object per line)")
    ap.add_argument("--insecure", action="store_true", help="skip TLS verification")
    ap.add_argument(
        "--discover",
        action="store_true",
        help="also scan headless WordPress hosts referenced by a non-WP front",
    )
    ap.add_argument("--workers", type=int, default=8, help="parallel workers (default 8)")
    ap.add_argument("--timeout", type=int, default=TIMEOUT, help="per-request timeout (s)")
    ap.add_argument("--user-agent", help="override the User-Agent header")
    args = ap.parse_args()

    TIMEOUT = max(1, args.timeout)
    if args.user_agent:
        USER_AGENT = args.user_agent

    targets = list(args.targets)
    if args.file:
        with open(args.file, encoding="utf-8") as fh:
            targets += [ln.strip() for ln in fh if ln.strip() and not ln.startswith("#")]
    if not targets:
        ap.error("no targets given")

    def scan_one(t: str) -> list[Result]:
        out = [assess(t, insecure=args.insecure)]
        if args.discover:
            for h in out[0].discovered:
                out.append(assess("https://" + h, insecure=args.insecure))
        return out

    workers = max(1, min(args.workers, len(targets)))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        batches = list(pool.map(scan_one, targets))

    exit_code = 0
    for batch in batches:
        for r in batch:
            if args.json:
                print(json.dumps(asdict(r)))
            else:
                print_human(r)
            if r.verdict in ("vulnerable-rce", "vulnerable-sqli"):
                exit_code = 2
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
