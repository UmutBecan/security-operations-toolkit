# Checks

Every finding has a **stable rule id** (`<check>/<slug>`), a status (`pass`, `info`, `warn`, `fail`, `error`) and,
where useful, a remediation. Ids are what SARIF, code scanning and any ticketing built on `--format json` key on;
they never change meaning (see `src/rules.mjs`). Status mapping to SARIF levels: `fail`/`error` → `error`,
`warn` → `warning`, `info` with a remediation → `note`, `pass` and plain `info` are not reported.

## mail

### MX, SPF, DMARC

| Rule id | Rule | Status |
|---|---|---|
| `mx/list` | MX list | info |
| `mx/null` | Null MX (RFC 7505, `0 .`): explicitly accepts no mail | info |
| `mx/implicit` | No MX but A/AAAA present: implicit MX (RFC 5321 §5.1) | warn |
| `mx/none` | No MX and no A/AAAA | info |
| `spf/missing` | No SPF record | fail |
| `spf/multiple` | More than one SPF record (RFC 7208 permerror) | fail |
| `spf/plus-all` | `+all` or bare `all` | fail |
| `spf/neutral-all` | `?all` | warn |
| `spf/no-all` | No `all` and no `redirect=` | warn |
| `spf/softfail`, `spf/hardfail` | `~all` / `-all` | pass |
| `spf/lookup-limit` | More than 10 DNS-querying terms at top level | fail |
| `spf/ptr` | `ptr` mechanism (deprecated) | warn |
| `dmarc/missing` | No DMARC record at `_dmarc.<domain>` or, via the RFC 9989 §4.10 tree walk, at a parent | fail |
| `dmarc/record` | Record found (inherited records are labelled and judged by `sp`, else `p`) | info |
| `dmarc/multiple` | More than one DMARC record | fail |
| `dmarc/policy-reject`, `dmarc/policy-quarantine` | `p=reject` / `p=quarantine` | pass |
| `dmarc/policy-none` | `p=none` | warn |
| `dmarc/policy-invalid` | Missing or invalid `p=` | fail |
| `dmarc/legacy-pct` | Legacy `pct` below 100 (removed in RFC 9989, ignored by its receivers) / `pct=100` | warn / info |
| `dmarc/test-mode` | `t=y` with `quarantine`/`reject` (RFC 9989 test mode) | warn |
| `dmarc/test-mode-noop`, `dmarc/invalid-t` | `t=y` with `p=none` / an invalid `t` value | info / warn |
| `dmarc/no-rua` | No `rua` | warn |
| `<check>/lookup-error` | The DNS query failed | error |

**DMARC discovery:** `_dmarc.<domain>` first, then the parent names of the RFC 9989 section 4.10 DNS tree walk
(at most 8 lookups; names with more than 8 labels are shortened to 7). The nearest valid record wins; a name with
several DMARC records contributes none. The `np` tag (non-existent subdomains) is not evaluated.

**Limitation:** SPF lookup counting does not follow nested `include:` chains.

### MTA-STS (RFC 8461)

Looks up the TXT record `_mta-sts.<domain>` (§3.1). Only if a valid record exists, fetches the policy from
`https://mta-sts.<domain>/.well-known/mta-sts.txt` (§3.2) and compares it with the domain's real MX hosts.

| Rule id | Rule | Status | RFC 8461 |
|---|---|---|---|
| `mta-sts/missing` | No `v=STSv1` TXT record. MTA-STS is optional hardening, so this is not a failure | info | §3.1 |
| `mta-sts/invalid-record` | More than one `v=STSv1` record, or `id` missing / not 1-32 alphanumerics (senders then assume no policy) | warn | §3.1 |
| `mta-sts/record` | Valid TXT record | info | §3.1 |
| `mta-sts/policy-unavailable` | TXT published but the policy cannot be fetched: non-200, any 3xx (never followed), TLS/DNS error, timeout, over 64 KB, or the host resolves to a non-public address | warn | §3.3 |
| `mta-sts/content-type` | Policy not served as `text/plain` | warn | §3.2 |
| `mta-sts/policy-invalid` | `version` not `STSv1`, `mode` not enforce/testing/none, `max_age` not a number or above 31557600, invalid or no `mx` | warn | §3.2 |
| `mta-sts/policy` | Parsed policy (mode, max_age, mx patterns) | info | §3.2 |
| `mta-sts/mode-enforce` | `mode: enforce` | pass | §5 |
| `mta-sts/mode-testing` | `mode: testing`: delivery is not blocked on TLS failures | warn | §5 |
| `mta-sts/mode-none` | `mode: none`: policy inactive (the documented way to withdraw MTA-STS) | info | §5, §8.3 |
| `mta-sts/mx-mismatch` | At least one actual MX host matches none of the policy's `mx` patterns | warn | §4.1 |
| `mta-sts/mx-covered` | Every MX host is covered | pass | §4.1 |
| `mta-sts/max-age-low` | `max_age` below 604800 s (one week) | warn | §3.2, §10 |
| `mta-sts/max-age-ok` | `max_age` at least one week | pass | §3.2 |

Notes on the RFC basis:

- **Pattern matching (§4.1):** a pattern is an exact name or `*.<suffix>`; the wildcard matches exactly one
  left-most label, so `*.example.com` matches `mail.example.com` but not `example.com` or `foo.bar.example.com`.
- **`max_age` threshold:** §3.2 says the value is "expected ... typically ... in the range of weeks or greater"
  and defines 31557600 (one year) as the maximum; §10 says to prefer values "as long as is practical". The RFC gives no
  numeric minimum, so one week (604800) is this tool's reading of "weeks"; it is a `warn`, never a `fail`.
  Not applied for `mode: none`, where §8.3 recommends a small `max_age` (e.g. one day) on purpose.
- **Redirects (§3.3):** "HTTP 3xx redirects MUST NOT be followed". The toolkit follows none, which also rules out
  redirects to another host.
- **Limits (§3.3):** suggested timeout one minute and maximum policy size 64 KB. The toolkit uses 10 s and 64 KB.
- **Not checked:** the MX hosts' own certificates and STARTTLS (§4.2), and whether the HTTPS certificate covers
  `mta-sts.<domain>` beyond what Node's default verification enforces (a failure is reported as `policy-unavailable`).
- The `version`/`v=` tokens are case-sensitive, as in the ABNF.

### TLS-RPT (RFC 8460)

Looks up the TXT record `_smtp._tls.<domain>` (§3).

| Rule id | Rule | Status | RFC 8460 |
|---|---|---|---|
| `tls-rpt/missing` | No `v=TLSRPTv1` record. Optional, so not a failure | info | §3 |
| `tls-rpt/invalid-record` | More than one `v=TLSRPTv1` record (senders assume it is not implemented), or `rua` missing / not `mailto:` or `https:` URIs | warn | §3 |
| `tls-rpt/present` | Valid record with `rua` | pass | §3 |

### DKIM (`--dkim-selector`)

A DKIM key lives at `<selector>._domainkey.<domain>` (RFC 6376 §3.6.2) and **selectors cannot be enumerated from
DNS**. Without `--dkim-selector` the toolkit therefore reports `dkim/not-evaluated` (info) and **never** reports DKIM
as missing. With `--dkim-selector s1,s2` (at most 10, each a valid DNS label sequence) each named selector is checked:

| Rule id | Rule | Status | Reference |
|---|---|---|---|
| `dkim/not-evaluated` | No selector given | info | |
| `dkim/selector-not-found` | No DKIM record at that selector. States that other selectors may still exist | warn | RFC 6376 §3.6.2 |
| `dkim/multiple-records` | Several key records at one selector; the first is evaluated | info | |
| `dkim/invalid-key` | `p=` absent, not valid base64, or not a parseable RSA key / 32-byte Ed25519 key | fail | RFC 6376 §3.6.1 |
| `dkim/revoked` | Empty `p=`: the key is revoked and signatures with this selector fail | warn | RFC 6376 §3.6.1 |
| `dkim/key-too-short` | RSA key under 1024 bits | fail | RFC 8301 §3.2 |
| `dkim/key-below-2048` | RSA key of 1024 to 2047 bits | warn | RFC 8301 §3.2 |
| `dkim/key-ok` | RSA key of 2048 bits or more, or a valid `k=ed25519` key | pass | RFC 8301 §3.2, RFC 8463 |
| `dkim/key-type-unknown` | `k=` other than `rsa`/`ed25519`; verifiers ignore it | info | RFC 6376 §3.6.1 |
| `dkim/testing` | `t=y`: verifiers do not treat failures differently from unsigned mail | info | RFC 6376 §3.6.1 |

## tls

| Rule id | Rule | Status |
|---|---|---|
| `tls/trusted` | Chain and hostname trusted by Node's CA store | pass |
| `tls/untrusted` | Not trusted (reason reported, e.g. expired, wrong host, self-signed) | fail |
| `tls/expired` | Expired | fail |
| `tls/expiring-soon` | Expires in < 14 days | fail |
| `tls/expiring` | Expires in < 30 days | warn |
| `tls/valid` | Valid for 30 days or more | pass |
| `tls/protocol-ok` | Negotiated TLS 1.2 / 1.3 | pass |
| `tls/legacy-protocol` | Negotiated anything older | fail |
| `tls/expiry-unknown`, `tls/connect-error` | Expiry unreadable / connection failed | error |

**Limitation:** only port 443, only the negotiated protocol version.

## headers

Fetches `https://<domain>/` (following redirects) and evaluates the final response.

| Rule id | Rule | Status |
|---|---|---|
| `headers/not-https` | Final URL not HTTPS | fail |
| `headers/hsts-missing`, `headers/hsts-short` | `Strict-Transport-Security` missing or `max-age` < 180 days | warn |
| `headers/csp-missing` | `Content-Security-Policy` missing | warn |
| `headers/nosniff-missing` | `X-Content-Type-Options: nosniff` missing | warn |
| `headers/framing-missing` | No CSP `frame-ancestors` and no `X-Frame-Options: DENY/SAMEORIGIN` | warn |
| `headers/referrer-missing` | `Referrer-Policy` not set | info |
| `headers/version-disclosed` | Version number in `Server` / `X-Powered-By` | info |
| `headers/request-error` | HTTPS request failed | error |
| `headers/response`, `headers/hsts-ok`, `headers/csp-ok`, `headers/nosniff-ok`, `headers/framing-ok`, `headers/referrer-ok` | Informational / passing results | info / pass |

**Limitation:** CSP is checked for presence only; its policy strength is not graded.
