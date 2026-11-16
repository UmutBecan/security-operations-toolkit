# security-operations-toolkit

[![test](https://github.com/UmutBecan/security-operations-toolkit/actions/workflows/test.yml/badge.svg)](https://github.com/UmutBecan/security-operations-toolkit/actions/workflows/test.yml)

Small, **defensive, read-only** checks for the external security posture of a
domain: email authentication records, TLS certificates and HTTP security headers.

Built for operations teams who want a quick, scriptable answer to
*"is anything obviously wrong with this domain?"*, with a clear reason and a
remediation hint for every finding.

**Run it now — no install, no dependencies (Node.js 20+):**

```bash
npx github:UmutBecan/security-operations-toolkit all yourdomain.com
```

> Need this every day for many domains, with change alerts and history?
> [**Korantix**](https://korantix.io) monitors domains from public data only:
> no credentials, no tenant access. [Scan a domain →](https://korantix.io/en?domain=yourdomain.com)

```text
$ node bin/secops.mjs tls expired.badssl.com
Target: expired.badssl.com

[TLS]
  FAIL  Certificate not trusted (CERT_HAS_EXPIRED)
        → Serve a certificate from a public CA that covers this hostname, with the full intermediate chain.
  FAIL  Certificate expired 4188 day(s) ago
        valid to Apr 12 23:59:59 2015 GMT; issuer COMODO CA Limited
  PASS  Negotiated TLSv1.2

Summary: 1 pass · 0 warn · 2 fail · 0 info · 0 error
```

Full sample output: [examples/example.com.txt](examples/example.com.txt)

---

## Verified run

Pin a release tag so results do not change under you:

```bash
npx --yes github:UmutBecan/security-operations-toolkit#v1.1.0 all example.com
```

Output below was captured on 2026-11-17 with Node.js v26.13.0 by running `node bin/secops.mjs all <domain>`
from the v1.1.0 source tree (exit code `0` for both). Certificate day counts and live DNS/HTTP data change over time.
The `#v1.1.0` form works once that tag is published to GitHub.

`example.com`:

```text
Target: example.com

[MX]
  INFO  Null MX (RFC 7505) — domain explicitly accepts no mail
[SPF]
  INFO  SPF record
        v=spf1 -all
  PASS  "-all" hardfail policy
  INFO  0 DNS-querying terms at top level (limit 10; nested includes not counted)
[DMARC]
  INFO  DMARC record
        v=DMARC1;p=reject;sp=reject;adkim=s;aspf=s
  PASS  Policy p=reject
  WARN  No aggregate reporting address (rua)
        → Add rua=mailto:<address> to receive aggregate reports.
[TLS]
  PASS  Certificate chain and hostname are trusted
  PASS  Certificate valid for 39 more day(s)
        valid to Dec 25 22:56:35 2026 GMT; issuer SSL Corporation
  PASS  Negotiated TLSv1.3
[HEADERS]
  INFO  Final response 200 from https://example.com/
  WARN  Strict-Transport-Security missing
        → Add "Strict-Transport-Security: max-age=31536000; includeSubDomains".
  WARN  Content-Security-Policy missing
        → Define a CSP; start in Content-Security-Policy-Report-Only mode.
  WARN  X-Content-Type-Options: nosniff missing
  WARN  No clickjacking protection
        → Add CSP "frame-ancestors 'self'" or "X-Frame-Options: DENY".
  INFO  Referrer-Policy not set (browser default applies)

Summary: 5 pass · 5 warn · 0 fail · 6 info · 0 error

Next: continuous monitoring and change alerts for example.com → https://korantix.io/en?domain=example.com
```

`github.com`:

```text
Target: github.com

[MX]
  INFO  1 MX record(s)
        0 github-com.mail.protection.outlook.com
[SPF]
  INFO  SPF record
        v=spf1 ip4:192.30.252.0/22 include:spf.protection.outlook.com include:_netblocks.google.com include:_netblocks2.google.com include:mail.zendesk.com include:_spf.salesforce.com include:servers.mcsv.net include:mktomail.com include:sendgrid.net ip4:62.253.227.114 ip4:166.78.69.169 ip4:166.78.69.170 ip4:166.78.71.131 ~all
  PASS  "~all" softfail policy
  INFO  8 DNS-querying terms at top level (limit 10; nested includes not counted)
[DMARC]
  INFO  DMARC record
        v=DMARC1; p=quarantine; sp=reject; pct=100; rua=mailto:dmarc@github.com; ruf=mailto:dmarc@github.com; fo=1
  PASS  Policy p=quarantine
  INFO  Legacy "pct=100" tag — removed in RFC 9989 and ignored by receivers that follow it
        pct=100 equals the default, so behaviour is unchanged.
        → Remove pct. To keep a policy in test mode use t=y (RFC 9989 section 4.7: failing mail is handled one level below the published policy); omit t or use t=n to enforce fully.
[TLS]
  PASS  Certificate chain and hostname are trusted
  PASS  Certificate valid for 72 more day(s)
        valid to Jan 27 23:59:59 2027 GMT; issuer Sectigo Limited
  PASS  Negotiated TLSv1.3
[HEADERS]
  INFO  Final response 200 from https://github.com/
  PASS  Strict-Transport-Security present
        max-age=31536000; includeSubdomains; preload
  PASS  Content-Security-Policy present (policy strength not evaluated)
  PASS  X-Content-Type-Options: nosniff
  PASS  Clickjacking protection (frame-ancestors or X-Frame-Options)
  PASS  Referrer-Policy: origin-when-cross-origin, strict-origin-when-cross-origin

Summary: 10 pass · 0 warn · 0 fail · 6 info · 0 error

Next: continuous monitoring and change alerts for github.com → https://korantix.io/en?domain=github.com
```

Run it on a schedule in CI: [examples/github-actions/domain-check.yml](examples/github-actions/domain-check.yml)
(weekly cron plus manual run, pinned to the release tag, fails the job on exit code `2`).

## Problem

Expired certificates, missing DMARC and weak HTTP headers are among the most common
and most preventable external findings. They are usually caught late, by a customer,
an auditor or an outage, because nobody checks them routinely.

## Architecture

```text
bin/secops.mjs         CLI: argument parsing, output, exit codes
src/domain.mjs         input validation (bare domain names only)
src/checks/mail.mjs    MX, SPF, DMARC      ─┐
src/checks/tls.mjs     certificate, TLS     ├─ lookup → evaluate → findings
src/checks/headers.mjs HTTP headers        ─┘
src/report.mjs         text / JSON output, exit code
```

Every check is split into a **lookup** (network) and a pure **evaluate** function
(no network). The evaluate functions are deterministic and fully unit tested.

## Technology

- Node.js ≥ 20, standard library only: **zero runtime dependencies**
- `node:dns`, `node:tls`, `fetch` for lookups
- `node:test` for tests

## Usage

```bash
node bin/secops.mjs all example.com
node bin/secops.mjs mail example.com
node bin/secops.mjs tls example.com
node bin/secops.mjs headers example.com --json
node bin/secops.mjs all example.com --no-hint   # omit the closing "Next:" line of the text report
node bin/secops.mjs --help
```

The text report ends with one `Next:` line pointing to continuous monitoring; `--no-hint` removes it and it is
never part of `--json` output.

Without cloning: `npx github:UmutBecan/security-operations-toolkit all example.com --json`

Example JSON output (real run of `mail example.com --json`, DMARC findings only):

```json
{
  "domain": "example.com",
  "checkedAt": "2026-11-16T21:12:04.428Z",
  "summary": { "pass": 2, "warn": 1, "fail": 0, "info": 4, "error": 0 },
  "findings": [
    { "check": "dmarc", "status": "info", "title": "DMARC record", "detail": "v=DMARC1;p=reject;sp=reject;adkim=s;aspf=s" },
    { "check": "dmarc", "status": "pass", "title": "Policy p=reject" },
    { "check": "dmarc", "status": "warn", "title": "No aggregate reporting address (rua)",
      "remediation": "Add rua=mailto:<address> to receive aggregate reports." }
  ]
}
```

| Exit code | Meaning |
|---|---|
| `0` | No `fail` or `error` findings |
| `1` | Usage error (bad arguments or invalid domain) |
| `2` | At least one `fail` or `error` finding |

The exit codes make it usable in cron jobs and CI pipelines.
See [examples/scheduled-check.sh](examples/scheduled-check.sh).

What each check covers, and what it deliberately does not: [docs/checks.md](docs/checks.md)

## Implementation

- **Deterministic rules, no scoring.** Each finding is `pass / warn / fail / info / error`
  with a title, optional detail and a remediation hint.
- **No false certainty.** Where a check cannot know something, it says so:
  e.g. DKIM is not checked because absence cannot be proven without a selector;
  CSP presence is reported, policy strength is not graded.
- **Canary tested.** The TLS check is verified against intentionally broken
  certificates from badssl.com: [examples/tls-canaries.txt](examples/tls-canaries.txt).

```bash
npm test     # 71 tests, no network required
```

## Security Considerations

- **Read-only and passive:** public DNS queries, one TLS handshake, one HTTPS `GET`.
  No port scanning, no fuzzing, no credential use, no exploitation.
- Input is restricted to bare domain names; URLs, IP addresses, ports and paths are rejected.
- Only check domains you own or are authorized to assess.
- See [SECURITY.md](SECURITY.md).

## Operational Considerations

- Results reflect one vantage point at one moment (DNS caching, CDNs and geo-routing
  can produce different answers elsewhere).
- The SPF DNS-lookup count is top-level only; nested `include:` chains are not resolved.
- TLS reports the negotiated protocol only — it is not a full cipher/protocol enumeration.

## Lessons Learned

- Separating lookup from evaluation made every rule testable without the network,
  and made false positives easy to reproduce and fix.
- A check that can silently pass is worse than no check: canary targets that
  *must* fail are part of verification.

## License

[MIT](LICENSE)

---

Need continuous multi-domain monitoring, executive PDF reports, and automated DMARC enforcement alerts? Visit **https://korantix.io**
