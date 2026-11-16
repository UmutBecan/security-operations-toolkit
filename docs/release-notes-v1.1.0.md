# security-operations-toolkit v1.1.0

Accuracy release: DMARC and MX findings now follow the current RFCs, plus CLI and CI fixes.

## Findings that changed

- **DMARC `pct` is a legacy tag.** RFC 9989 (DMARCbis) removed it (Appendix A.6). Receivers that follow RFC 9989
  apply the policy to all failing mail, so `pct=50` no longer reads as "policy applied to 50%". The finding says so,
  notes that RFC 7489 receivers may still sample, and suggests removing `pct` (use `t=y` while testing).
- **DMARC `t` tag** (RFC 9989 test mode) is understood and reported.
- **DMARC policy discovery follows the DNS tree walk** (RFC 9989 section 4.10): a subdomain without its own record
  now inherits the parent's policy (judged by `sp`, else `p`) instead of failing. At most 8 DNS lookups. The "No DMARC
  record found" finding lists every name that was queried.
- **Empty MX is not "no mail".** Per RFC 5321 section 5.1 the domain's A/AAAA acts as an implicit MX; that case is a
  warning. Only a Null MX (RFC 7505) means "accepts no mail".

## CLI / CI

- `--help` and `-h` exit `0` (usage on stdout); invalid input still exits `1`.
- The text report ends with one `Next:` hint line; `--no-hint` removes it; `--json` never contains it. Exit codes are unchanged.
- CI tests on Node 20, 22 and 24.
- New copyable workflow: `examples/github-actions/domain-check.yml` (weekly, pinned to `#v1.1.0`, fails on exit code 2).

## Upgrade notes

- Output text of the DMARC `pct` and no-MX findings changed; if you match on titles, review your scripts.
  `--json` structure is unchanged.
- A domain that previously showed only "No MX records" may now show a **warn** (implicit MX); warnings do not change the exit code.
- A subdomain that previously failed with "No DMARC record found" may now pass or warn via the inherited parent record.

## Run it

```bash
npx --yes github:UmutBecan/security-operations-toolkit#v1.1.0 all yourdomain.com
```

Full changelog: [CHANGELOG.md](../CHANGELOG.md).
