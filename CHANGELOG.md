# Changelog

## v0.2.0 — 2026-11-17

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
