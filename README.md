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

1. **Fingerprints the WordPress core version** from public sources: the
   `generator` meta tag, the RSS feed generator (`?v=`), `readme.html`, and the
   `/wp-json/` index.
2. **Compares** the version to the known-vulnerable ranges.
3. **Checks the REST batch route** with a benign `OPTIONS` request — which
   returns the route schema *without ever invoking the handler* — to tell whether
   an edge mitigation is in place.

No request triggers the vulnerability. No `POST /wp-json/batch/v1`, no
`author_exclude`, no SQL. If the core version is hidden, the tool says so rather
than guessing (confirming wp2shell blindly would require exploiting it).

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
./wp2shell_detect.py --targets hosts.txt        # one host per line
```

Exit code `2` if any target is found vulnerable (handy in CI / cron sweeps).

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
