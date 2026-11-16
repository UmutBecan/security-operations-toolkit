# Changelog

## v1.2.0 — unreleased

Pipeline release: many domains in one run, SARIF for GitHub code scanning, a management report, and the
transport-security records mail operators are asked about (MTA-STS, TLS-RPT, DKIM for known selectors).
Exit codes are unchanged (`0` / `1` / `2`). `--json` for a single domain keeps its shape; findings gained an `id`.

### Added

- **Batch mode:** `secops all --file domains.txt` (also `mail`, `tls`, `headers`; `-` reads stdin). One domain per
  line, `#` comments and blank lines ignored, duplicates removed, every line validated with the single-domain
  validator. Invalid lines abort with exit `1` and `file:line` messages (`--skip-invalid` warns and continues).
  Bounded concurrency (`--concurrency`, default 4, max 16). Per-domain output plus a summary table; the exit code is
  the worst across all domains. `--json` returns `{ checkedAt, summary, domains: [...] }`.
- **`--format text|json|sarif|markdown`.** `--json` stays as an alias of `--format json`.
- **SARIF 2.1.0** (`--format sarif`) for GitHub code scanning: `fail`/`error` → `error`, `warn` → `warning`,
  actionable `info` → `note`, `pass` and plain `info` omitted. Each result is anchored to the line of the domain in the
  `--file` (or `domains.txt`), with the domain in the message, `logicalLocations` and a stable
  `partialFingerprints.primaryLocationLineHash`. `validateSarifShape` checks the properties GitHub documents as required.
  `examples/github-actions/code-scanning.yml` runs it and uploads with `github/codeql-action/upload-sarif@v4`.
- **Stable rule ids** on every finding (`dmarc/legacy-pct`, `mx/implicit`, `tls/expired`, ...), with a catalog in
  `src/rules.mjs` and a test that keeps it in sync with the checks. Listed in `docs/checks.md`.
- **`--format markdown`:** summary table per domain, then findings with remediation. Target-controlled text is escaped.
- **MTA-STS (RFC 8461):** `_mta-sts.<domain>` TXT (§3.1), then the policy from `https://mta-sts.<domain>/.well-known/mta-sts.txt`
  (§3.2): `version`, `mode`, `mx`, `max_age`. Findings: missing (info), invalid record, policy unavailable, wrong media type,
  invalid policy, `testing` (warn), MX hosts not covered by the `mx` patterns (§4.1, warn), `max_age` under one week (§3.2/§10, warn).
- **TLS-RPT (RFC 8460 §3):** `_smtp._tls.<domain>`; missing is info, a valid `rua` passes, an invalid record warns.
- **DKIM (`--dkim-selector s1,s2`):** checks `<selector>._domainkey.<domain>`: missing key at that selector, revoked
  (empty `p=`, RFC 6376 §3.6.1), RSA key size (RFC 8301 §3.2: under 1024 fail, under 2048 warn), Ed25519 (RFC 8463),
  `t=y`. Without a selector the report says DKIM was **not evaluated**; it is never reported as missing.
- **Output hygiene:** control characters in text taken from DNS/HTTP are replaced before printing.
- Tests: 71 → 177. Offline throughout (injected lookups/fetch, a loopback HTTP server for the fetcher).

### Security

- The MTA-STS policy fetch is SSRF-guarded: host derived from the validated domain only, internal names and IP
  literals refused, connect-time address must be public (no DNS-rebinding gap), no redirects followed (RFC 8461 §3.3),
  HTTPS on 443 only, 10 s timeout, 64 KB cap. Details in `SECURITY.md`.

### Changed

- The text report has new `[MTA-STS]`, `[TLS-RPT]` and `[DKIM]` sections under `mail`/`all`. Scripts that parse the
  text report should use `--format json` (findings now carry `id`) instead.
- Unknown command-line options are now a usage error (exit `1`) instead of being read as the domain argument.

## v1.1.0 — 2026-11-17

Follows the existing `v1.0.0` tag (`9f2859e`, published without release notes).

### Changed (findings)

- **DMARC `pct` is now reported as a legacy tag.** RFC 9989 (DMARCbis, May 2026) removed `pct`
  (Appendix A.6; registered as *historic*). Under section 4.7 unknown tags MUST be ignored, so receivers that follow
  RFC 9989 apply the policy to all failing mail. `pct` below 100 is a `warn` (not an enforcement percentage) and
  `pct=100` is `info`; both carry a remediation. Receivers still on RFC 7489 may sample by `pct`, which the finding says.
- **DMARC `t` tag.** The RFC 9989 replacement for `pct=0`/`pct=100` is understood: `t=y` is a `warn` when the policy
  is `quarantine`/`reject` (failing mail is handled one level lower), `info` with `p=none`; an invalid value warns.
- **DMARC discovery follows the RFC 9989 section 4.10 DNS tree walk.** If `_dmarc.<domain>` has no record, parent names
  are queried (bounded: at most 8 lookups, names above 8 labels shortened to 7). An inherited record is labelled as
  such and judged by `sp` (falling back to `p`). "No DMARC record found" now lists every name that was queried.
- **No MX no longer means "does not receive mail".** Per RFC 5321 section 5.1 a domain without MX records uses its
  own A/AAAA as an implicit MX, so that case is now a `warn` with the addresses and a hint to publish explicit MX
  or a Null MX. Only a Null MX (RFC 7505, `0 .`) is reported as "accepts no mail". No MX and no A/AAAA is `info`.

### Added

- `--help` / `-h` print usage on stdout and exit `0`. Invalid input still prints usage on stderr and exits `1`.
- One-line next-step hint at the end of the text report; `--no-hint` suppresses it. It is never part of `--json`.
  Exit codes are unchanged.
- `examples/github-actions/domain-check.yml`: scheduled workflow pinned to a release tag; fails on exit code 2.
- CI runs the tests on Node 20, 22 and 24.
- `src/cli.mjs`: CLI logic moved out of `bin/secops.mjs` so it can be tested offline (checks and output are injectable).

### Tests

- 46 → 71 tests. One existing assertion in `test/mail.test.mjs` was updated for the new `pct` wording.
  New tests live in `test/mail.rfc.test.mjs` and `test/cli.extra.test.mjs`.

### References

- RFC 9989, DMARC: sections 4.7, 4.10, 4.10.1, Appendix A.6, C.5.2 — https://www.rfc-editor.org/rfc/rfc9989.html
- RFC 5321, SMTP: section 5.1 (implicit MX) — https://www.rfc-editor.org/rfc/rfc5321.html#section-5.1
- RFC 7505, Null MX: section 3 — https://www.rfc-editor.org/rfc/rfc7505.html

## v0.1.0

Initial release: `mail` (MX, SPF, DMARC), `tls`, `headers`, `all`, `--json`, exit codes 0/1/2.
