# security-operations-toolkit

[![test](https://github.com/UmutBecan/security-operations-toolkit/actions/workflows/test.yml/badge.svg)](https://github.com/UmutBecan/security-operations-toolkit/actions/workflows/test.yml)

Small, **defensive, read-only** checks for the external security posture of a
domain: email authentication (SPF, DMARC, MTA-STS, TLS-RPT, and DKIM for selectors you name), TLS certificates and
HTTP security headers. Runs one domain or a whole list and reports as text, JSON, Markdown or SARIF for GitHub
code scanning.

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

## For pipelines

Check a list of domains, fail or alert on the worst result, and get findings into GitHub code scanning.

**1. Batch mode.** `domains.txt` (see [examples/domains.example.txt](examples/domains.example.txt)):

```text
# Domains to check, one per line. Blank lines and # comments are ignored.
github.com
google.com
example.com   # IANA documentation domain
```

```bash
node bin/secops.mjs all --file examples/domains.example.txt --no-hint
```

Each domain gets its full report, then a summary table. The exit code is the worst across all domains
(`0` none fail, `2` at least one `fail`/`error`, `1` usage error such as an invalid line). Real output, captured
2026-11-16 22:10 UTC with Node.js v26.13.0, trimmed to the new parts (the full text report of every domain is omitted):

```text
[MTA-STS]                                   <- google.com
  INFO  MTA-STS TXT record
        v=STSv1; id=20210803T010101;
  INFO  MTA-STS policy
        mode enforce; max_age 86400 s (1 day); mx smtp.google.com, aspmx.l.google.com, *.aspmx.l.google.com
  PASS  MTA-STS mode=enforce
  PASS  Every MX host is covered by the policy
  WARN  max_age is short (86400 s (1 day))
        RFC 8461 section 3.2: the value is typically in the range of weeks or greater, ...
        → Use at least max_age: 604800 (one week); 31557600 (one year, the maximum) once the policy is stable.
[TLS-RPT]
  PASS  TLS-RPT reporting is published
        v=TLSRPTv1;rua=mailto:sts-reports@google.com

Batch summary: 3 domain(s)
  DOMAIN       FAIL  ERROR  WARN  PASS  RESULT
  github.com      0      0     0    10  OK
  google.com      0      0     4     9  WARN
  example.com     0      0     5     5  WARN
  TOTAL           0      0     9    24  WARN
```

`--json` with `--file` returns one document: `{ "checkedAt", "summary", "domains": [ { "domain", "summary", "findings" } ] }`.
Every finding now also carries its stable rule `id`.

**2. Markdown report** for people who do not read terminals. `--format markdown` prints a summary table and, per domain,
only what needs attention, with its remediation (same run, trimmed):

```markdown
| Domain | Status | Fail | Error | Warn | Pass |
|---|---|---:|---:|---:|---:|
| github.com | OK | 0 | 0 | 0 | 10 |
| google.com | REVIEW | 0 | 0 | 4 | 9 |
| example.com | REVIEW | 0 | 0 | 5 | 5 |

### google.com

| Severity | Area | Finding | Remediation |
|---|---|---|---|
| Warn | mta-sts | max\_age is short (86400 s (1 day)). RFC 8461 section 3.2: ... | Use at least max\_age: 604800 (one week); ... |
| Warn | headers | Strict-Transport-Security missing | Add "Strict-Transport-Security: max-age=31536000; includeSubDomains". |
```

**3. GitHub code scanning (SARIF 2.1.0).** `--format sarif` prints a SARIF log on stdout:

```bash
node bin/secops.mjs all --file examples/domains.example.txt --format sarif > secops.sarif
```

Same three domains: 14 results from 9 rules. One rule and one result, trimmed:

```json
{ "id": "mta-sts/max-age-low",
  "shortDescription": { "text": "MTA-STS max_age below one week (RFC 8461 sections 3.2 and 10)" },
  "help": { "text": "Use at least max_age: 604800; 31557600 (the maximum) once the policy is stable." },
  "defaultConfiguration": { "level": "warning" } }

{ "ruleId": "mta-sts/max-age-low", "level": "warning",
  "message": { "text": "google.com: max_age is short (86400 s (1 day)). RFC 8461 section 3.2: ... Remediation: Use at least max_age: 604800 ..." },
  "locations": [ { "physicalLocation": {
      "artifactLocation": { "uri": "examples/domains.example.txt" },
      "region": { "startLine": 3, "startColumn": 1, "endLine": 3, "endColumn": 1 } },
    "logicalLocations": [ { "name": "google.com", "kind": "resource" } ] } ],
  "partialFingerprints": { "primaryLocationLineHash": "c991f851db06c79553ccaecfe6e2ce7f:1" } }
```

- Findings are about domains, not source files, so each result is anchored to the **line of the domain in the file
  you passed with `--file`** (or to `domains.txt` for a single-domain run). The domain is in the message, in
  `logicalLocations` and in the fingerprint. The fingerprint does not depend on the line, so reordering the file does
  not reopen alerts.
- `fail`/`error` become `error`, `warn` becomes `warning`, `info` that carries a remediation becomes `note`. `pass` and
  plain `info` (record dumps) are not reported, so a clean domain produces no alerts.
- A run of this command is saved as [test/fixtures/real-run.sarif.json](test/fixtures/real-run.sarif.json) and a test
  (`validateSarifShape` in `src/sarif.mjs`) checks it for the properties GitHub's
  [SARIF support for code scanning](https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning)
  lists as required (`$schema`, `version`, `runs`, `tool.driver.name` and `rules` with `id` and descriptions, results
  with `message`, `locations` including a full `region`, and `partialFingerprints`). That is a structural check, not a
  full JSON-Schema validation, and this release has **not** been uploaded to a live GitHub repository yet.

Workflow: [examples/github-actions/code-scanning.yml](examples/github-actions/code-scanning.yml) runs the CLI weekly,
treats exit code `2` (findings) as success so the upload still happens, fails on any other error, and uploads with
`github/codeql-action/upload-sarif@v4` (needs `security-events: write`; `actions: read` for private repositories).
Rule ids are stable (`dmarc/legacy-pct`, `mx/implicit`, `tls/expired`, `mta-sts/mx-mismatch`, ...); the full list is in
[docs/checks.md](docs/checks.md).

Safety notes for unattended use: the only URL the tool fetches that it built itself is the MTA-STS policy, and that
fetch refuses internal names and non-public addresses, follows no redirects and is size- and time-capped
([SECURITY.md](SECURITY.md)).

## Problem

Expired certificates, missing DMARC and weak HTTP headers are among the most common
and most preventable external findings. They are usually caught late, by a customer,
an auditor or an outage, because nobody checks them routinely.

## Architecture

```text
bin/secops.mjs         CLI: argument parsing, output, exit codes
src/domain.mjs         input validation (bare domain names only)
src/batch.mjs          domain-list parsing, bounded concurrency
src/checks/mail.mjs    MX, SPF, DMARC, MTA-STS, TLS-RPT, DKIM ─┐
src/checks/tls.mjs     certificate, TLS                         ├─ lookup → evaluate → findings
src/checks/headers.mjs HTTP headers                            ─┘
src/netsafe.mjs        SSRF guard for the MTA-STS policy fetch
src/rules.mjs          stable rule ids and help text
src/report.mjs         text output, exit code
src/sarif.mjs          SARIF 2.1.0 (GitHub code scanning)
src/markdown.mjs       management-readable report
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
node bin/secops.mjs mail example.com --dkim-selector s1,selector2   # also check DKIM keys you know exist
node bin/secops.mjs all --file domains.txt      # many domains, see "For pipelines"
node bin/secops.mjs all example.com --format markdown
node bin/secops.mjs --help
```

| Option | Meaning |
|---|---|
| `--format <f>` | `text` (default), `json`, `sarif` or `markdown`. `--json` is an alias of `--format json`. |
| `--file <path>` | Check every domain in a file: one per line, `#` comments and blank lines ignored, duplicates removed, each line validated like a single domain. `-` reads stdin. |
| `--concurrency <n>` | Domains checked in parallel (default 4, max 16). |
| `--skip-invalid` | With `--file`, warn about invalid lines and continue. Default: exit `1` before checking anything. |
| `--dkim-selector s1,s2` | Also check `<selector>._domainkey.<domain>` (`mail`, `all`). Without it DKIM is reported as *not evaluated*, never as missing: selectors cannot be enumerated from DNS. |
| `--no-hint` | Omit the one-line next-step hint of a single-domain text report. |

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
  e.g. DKIM is only checked for selectors you name, because absence cannot be proven without one;
  CSP presence is reported, policy strength is not graded.
- **Canary tested.** The TLS check is verified against intentionally broken
  certificates from badssl.com: [examples/tls-canaries.txt](examples/tls-canaries.txt).

```bash
npm test     # 177 tests, no network required
```

## Security Considerations

- **Read-only and passive:** public DNS queries, one TLS handshake, one HTTPS `GET` (plus one for the MTA-STS
  policy when the domain publishes one; SSRF-guarded, see [SECURITY.md](SECURITY.md)).
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
