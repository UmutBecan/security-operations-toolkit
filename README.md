# security-operations-toolkit

[![test](https://github.com/UmutB34/security-operations-toolkit/actions/workflows/test.yml/badge.svg)](https://github.com/UmutB34/security-operations-toolkit/actions/workflows/test.yml)

Small, **defensive, read-only** checks for the external security posture of a
domain: email authentication records, TLS certificates and HTTP security headers.

Built for operations teams who want a quick, scriptable answer to
*"is anything obviously wrong with this domain?"* — with a clear reason and a
remediation hint for every finding.

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

## Problem

Expired certificates, missing DMARC and weak HTTP headers are among the most common
and most preventable external findings. They are usually caught late — by a customer,
an auditor or an outage — because nobody checks them routinely.

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

- Node.js ≥ 20, standard library only — **zero runtime dependencies**
- `node:dns`, `node:tls`, `fetch` for lookups
- `node:test` for tests

## Usage

```bash
node bin/secops.mjs all example.com
node bin/secops.mjs mail example.com
node bin/secops.mjs tls example.com
node bin/secops.mjs headers example.com --json
```

| Exit code | Meaning |
|---|---|
| `0` | No `fail` or `error` findings |
| `1` | Usage error (bad arguments or invalid domain) |
| `2` | At least one `fail` or `error` finding |

The exit codes make it usable in cron jobs and CI pipelines —
see [examples/scheduled-check.sh](examples/scheduled-check.sh).

What each check covers, and what it deliberately does not: [docs/checks.md](docs/checks.md)

## Implementation

- **Deterministic rules, no scoring.** Each finding is `pass / warn / fail / info / error`
  with a title, optional detail and a remediation hint.
- **No false certainty.** Where a check cannot know something, it says so —
  e.g. DKIM is not checked because absence cannot be proven without a selector;
  CSP presence is reported, policy strength is not graded.
- **Canary tested.** The TLS check is verified against intentionally broken
  certificates from badssl.com: [examples/tls-canaries.txt](examples/tls-canaries.txt).

```bash
npm test     # 46 unit tests, no network required
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
