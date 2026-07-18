# wp2shell-detect

Blackbox, **non-intrusive** detector for **wp2shell** — the pre-authentication
RCE chain in WordPress core disclosed on 2026-07-17:

- **CVE-2026-63030** — route confusion in the REST batch endpoint
  (`/wp-json/batch/v1`): a sub-request whose path fails `wp_parse_url()` lands in
  the validation array but not the handler array, desynchronising the two.
- **CVE-2026-60137** — SQL injection in `WP_Query`'s `author__not_in` handling,
  reachable pre-auth through that route confusion.

Chained, they let an anonymous attacker forge an administrator account and drop a
plugin webshell — on a **default install**, no plugin or theme required.

Full technical writeup:
<https://own2pwn.fr/articles/appsec/wp2shell-wordpress-rce>

## What this tool does (and does not)

It **detects exposure**. It **does not exploit** anything. Every request it makes
is a normal, read-only request a crawler could send:

1. **Fingerprints the WordPress core version** from many public sources, so a
   hardened install that strips the `generator` tag is still identified: the
   `generator` meta tag, **core asset `?ver=`** (on `/wp-includes/` and
   `/wp-admin/` assets, which track core), the RSS feed generator (`?v=`),
   `/wp-links-opml.php`, the login page assets, `/wp-includes/version.php`,
   `readme.html`, and the `/wp-json/` index. Sources are cross-checked and a
   **confidence** (`high` when ≥2 agree) is reported.
2. **Compares** the version to the known-vulnerable ranges.
3. **Checks the REST batch route** with a benign `OPTIONS` request (and the REST
   index) — which returns the route schema *without ever invoking the handler* —
   to tell whether an edge mitigation is in place.
4. **Discovers headless WordPress back-ends.** If the target front isn't WP but
   references a WordPress host on the same domain (via CSP, the `Link` header or
   asset URLs — common with headless/Next.js fronts), the tool reports it, and
   `--discover` scans it too.

No request triggers the vulnerability. No `POST /wp-json/batch/v1`, no
`author_exclude`, no SQL. If the core version is hidden, the tool says so rather
than guessing (confirming wp2shell blindly would require exploiting it).

**Resilience:** retries with backoff, gzip/deflate decoding, `https→http`
fallback, cross-host redirect following, a browser-like User-Agent (overridable),
and parallel multi-target scanning.

## Vulnerable ranges

| Range | Exposure | Fixed in |
|-------|----------|----------|
| 6.8.0 – 6.8.5 | SQL injection only (no RCE) | 6.8.6 |
| 6.9.0 – 6.9.4 | **pre-auth RCE** | 6.9.5 |
| 7.0.0 – 7.0.1 | **pre-auth RCE** | 7.0.2 |

## Usage

Zero dependencies. Python 3.8+.

```bash
./wp2shell_detect.py https://example.com
./wp2shell_detect.py --json https://a.example https://b.example
./wp2shell_detect.py --targets hosts.txt --workers 16   # parallel sweep
./wp2shell_detect.py --discover https://front.example   # follow headless WP
```

Options: `--json`, `--discover`, `--workers N`, `--timeout S`, `--user-agent UA`,
`--insecure`, `--targets FILE`. Exit code `2` if any target is found vulnerable
(handy in CI / cron sweeps).

### Headless WordPress

Modern sites often serve a JS/Next.js front on `www.` and keep WordPress on a
sibling host (`wordpress.`, `wp.`, `cms.`). Scanning `www.` then returns
`not WordPress` — correctly, because that host isn't WordPress. Point the scan at
the WordPress host, or pass `--discover` to have the tool find and scan it from
the front's CSP / `Link` header / asset URLs automatically.

Example:

```
[!!] https://blog.example.com  ->  VULNERABLE (pre-auth RCE)
      version : 6.9.3  (generator meta tag=6.9.3, RSS feed generator=6.9.3)
      batch   : reachable  (/wp-json/batch/v1)
      cves    : CVE-2026-63030, CVE-2026-60137
      note    : WordPress 6.9.3 is in the wp2shell pre-auth RCE range. REST batch endpoint reachable — no edge mitigation.
```

## Mitigation

Patch WordPress core to **6.8.6 / 6.9.5 / 7.0.2** or later. If patching must
wait, block the batch route at the edge (`/wp-json/batch/v1` and
`?rest_route=/batch/v1`) or via a must-use plugin hooking `rest_pre_dispatch`,
then audit for rogue admin accounts and unknown plugins.

## Legal

For authorised assessment only. Running this against systems you neither own nor
are mandated to test may be illegal in your jurisdiction. You are responsible for
how you use it.

## License

MIT — see [LICENSE](LICENSE). By own2pwn.
